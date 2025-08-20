package anyads

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PollingSDK - основной клиент SDK.
type PollingSDK struct {
	apiKey           string
	interval         time.Duration
	sdkVersion       string
	apiBaseURL       string
	instanceIDPath   string
	httpClient       *http.Client
	instanceID       string
	fingerprint      string
	broadcastHandler BroadcastHandler
	ctx              context.Context
	cancelFunc       context.CancelFunc
	isPolling        bool
}

// NewClient создает новый экземпляр SDK.
func NewClient(apiKey string, interval time.Duration) (*PollingSDK, error) {
	if apiKey == "" || len(apiKey) < 7 || !strings.HasPrefix(apiKey, "anyads_") {
		return nil, ErrInvalidAPIKey
	}

	ctx, cancel := context.WithCancel(context.Background())

	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("не удалось получить домашнюю директорию пользователя: %w", err)
	}
	instanceIDPath := currentUser.HomeDir + "/.anyads_instance_id"

	sdk := &PollingSDK{
		apiKey:           apiKey,
		interval:         interval,
		sdkVersion:       "go-0.1.0",
		apiBaseURL:       "https://api.anyads.online/v1",
		instanceIDPath:   instanceIDPath,
		ctx:              ctx,
		cancelFunc:       cancel,
	}

	sdk.fingerprint = sdk.getEnvironmentFingerprint()
	instanceID, err := sdk.getOrCreateInstanceID()
	if err != nil {
		return nil, fmt.Errorf("ошибка инициализации Instance ID: %w", err)
	}
	sdk.instanceID = instanceID

	sdk.httpClient = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &headerTransport{
			apiKey:      sdk.apiKey,
			instanceID:  sdk.instanceID,
			fingerprint: sdk.fingerprint,
			sdkVersion:  sdk.sdkVersion,
			transport:   http.DefaultTransport,
		},
	}
	
	log.Printf("[AnyAds SDK] SDK инициализирован. Instance ID: %s\n", sdk.instanceID)
	return sdk, nil
}

func (sdk *PollingSDK) getOrCreateInstanceID() (string, error) {
	data, err := os.ReadFile(sdk.instanceIDPath)
	if err == nil && len(data) > 0 {
		log.Printf("[AnyAds SDK] Найден существующий Instance ID: %s\n", string(data))
		return string(data), nil
	}

	newID := "inst_" + uuid.New().String()
	err = os.WriteFile(sdk.instanceIDPath, []byte(newID), 0644)
	if err != nil {
		return "", fmt.Errorf("не удалось записать Instance ID в файл: %w", err)
	}
	log.Printf("[AnyAds SDK] Создан новый Instance ID: %s. Регистрируем на сервере...\n", newID)

	err = sdk.registerInstance(newID)
	return newID, err
}

func (sdk *PollingSDK) registerInstance(instanceID string) error {
	payload := map[string]string{
		"api_key":       sdk.apiKey,
		"instance_id":   instanceID,
		"fingerprint":   sdk.fingerprint,
		"sdk_version":   sdk.sdkVersion,
	}
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("ошибка сериализации данных для регистрации: %w", err)
	}

	req, err := http.NewRequestWithContext(sdk.ctx, "POST", sdk.apiBaseURL+"/sdk/register-instance", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("ошибка создания запроса на регистрацию: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("сетевая ошибка при регистрации Instance ID: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("не удалось зарегистрировать Instance ID, сервер ответил %d: %s", resp.StatusCode, string(body))
	}
	log.Printf("[AnyAds SDK] Новый Instance ID %s успешно зарегистрирован.\n", instanceID)
	return nil
}

func (sdk *PollingSDK) getEnvironmentFingerprint() string {
	var macAddr string
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
				macAddr = i.HardwareAddr.String()
				if macAddr != "" {
					break
				}
			}
		}
	}
	hostname, _ := os.Hostname()
	systemInfo := fmt.Sprintf("%s-%s-%s", runtime.GOOS, runtime.GOARCH, hostname)
	rawFingerprint := fmt.Sprintf("%s-%s", macAddr, systemInfo)
	hash := sha256.Sum256([]byte(rawFingerprint))
	return hex.EncodeToString(hash[:])
}

func (sdk *PollingSDK) pollLoop() {
	ticker := time.NewTicker(sdk.interval)
	defer ticker.Stop()

	sdk.poll()

	for {
		select {
		case <-sdk.ctx.Done():
			log.Println("[AnyAds SDK] Опрос остановлен.")
			return
		case <-ticker.C:
			sdk.poll()
		}
	}
}

func (sdk *PollingSDK) poll() {
	log.Println("[AnyAds SDK] Проверка наличия рекламных задач...")
	
	req, err := http.NewRequestWithContext(sdk.ctx, "GET", sdk.apiBaseURL+"/tasks/bots/newsletters", nil)
	if err != nil {
		log.Printf("[AnyAds SDK] Ошибка создания запроса: %v\n", err)
		return
	}

	resp, err := sdk.httpClient.Do(req)
	if err != nil {
		log.Printf("[AnyAds SDK] Ошибка сети при опросе: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		log.Println("[AnyAds SDK] Нет активных задач.")
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("[AnyAds SDK] Ошибка API при опросе, статус: %d\n", resp.StatusCode)
		return
	}

	var task AdTask
	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		log.Printf("[AnyAds SDK] Ошибка парсинга ответа от сервера: %v\n", err)
		return
	}

	if sdk.broadcastHandler != nil {
		log.Printf("[AnyAds SDK] Получена новая рекламная задача: %s\n", task.TaskID)
		go sdk.broadcastHandler(task)
	} else {
		log.Println("[AnyAds SDK] Получена задача, но обработчик не установлен!")
	}
}

// OnBroadcastReceived устанавливает коллбэк-функцию.
func (sdk *PollingSDK) OnBroadcastReceived(handler BroadcastHandler) {
	sdk.broadcastHandler = handler
}

// Start запускает фоновый опрос.
func (sdk *PollingSDK) Start() error {
	if sdk.broadcastHandler == nil {
		return ErrHandlerNotSet
	}
	if sdk.isPolling {
		return ErrPollingAlreadyRun
	}
	
	go sdk.pollLoop()
	sdk.isPolling = true
	log.Println("[AnyAds SDK] Фоновый опрос запущен.")
	return nil
}

// Stop останавливает фоновый опрос.
func (sdk *PollingSDK) Stop() {
	sdk.cancelFunc()
	sdk.isPolling = false
}

// --- ПОЛНОСТЬЮ РЕАЛИЗОВАННЫЙ МЕТОД ---
// ProcessVerificationCode отправляет код верификации на сервер.
func (sdk *PollingSDK) ProcessVerificationCode(code string) error {
	if !strings.HasPrefix(code, "/verify_anyads_") {
		return fmt.Errorf("неверный формат команды верификации")
	}
	
	verificationCode := strings.TrimPrefix(code, "/")
	log.Printf("[AnyAds SDK] Получена верификационная команда: %s\n", verificationCode)

	payload := map[string]string{
		"verification_code": verificationCode,
	}
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("ошибка сериализации данных для верификации: %w", err)
	}
	
	req, err := http.NewRequestWithContext(sdk.ctx, "POST", sdk.apiBaseURL+"/sdk/verify", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("ошибка создания запроса на верификацию: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	
	// Используем основной httpClient, так как верификация требует аутентификации
	resp, err := sdk.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("сетевая ошибка при верификации: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("не удалось верифицировать инстанс, сервер ответил %d: %s", resp.StatusCode, string(body))
	}

	log.Println("[AnyAds SDK] Код верификации успешно отправлен на сервер.")
	return nil
}

// Вспомогательная структура для добавления заголовков
type headerTransport struct {
	apiKey      string
	instanceID  string
	fingerprint string
	sdkVersion  string
	transport   http.RoundTripper
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", "Bearer "+t.apiKey)
	req.Header.Add("X-Instance-ID", t.instanceID)
	req.Header.Add("X-Environment-Fingerprint", t.fingerprint)
	req.Header.Add("User-Agent", "AnyAdsGoSDK/"+t.sdkVersion)
	return t.transport.RoundTrip(req)
}