<p align="center">
  <a href="https://pkg.go.dev/github.com/maomedia/AnyAds-SDK-GoLang"><img src="https://pkg.go.dev/badge/github.com/maomedia/AnyAds-SDK-GoLang" alt="Go Reference"></a>
  <a href="#"><img src="https://img.shields.io/github/v/release/maomedia/AnyAds-SDK-GoLang" alt="Release"></a>
</p>

Официальный Go SDK для интеграции вашего Telegram-бота с рекламной платформой **AnyAds.online**. Написан с учетом идиом Go, обеспечивает высокую производительность и минимальное потребление ресурсов.

## 🚀 Быстрый старт

### Шаг 1: Установка

Добавьте SDK как зависимость в ваш проект с помощью `go get`.

```bash
go get github.com/maomedia/AnyAds-SDK-GoLang@latest
```

### Шаг 2: Получение API Key

1.  Зарегистрируйтесь на [**anyads.online**](https://anyads.online).
2.  Добавьте вашего бота в разделе "Площадки" и скопируйте сгенерированный **`API_KEY`**.

### Шаг 3: Интеграция в код

Вот простой пример консольного приложения, которое инициализирует SDK, запускает фоновый опрос и обрабатывает рекламные задачи.

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"anyads.online/sdk-go" // Используйте ваш реальный путь к модулю
)

// handleAdTask - это ваша функция-обработчик для рекламных задач.
// SDK вызовет ее в отдельной горутине.
func handleAdTask(task anyads.AdTask) {
	fmt.Printf(">>> ПОЛУЧЕНА НОВАЯ РЕКЛАМНАЯ ЗАДАЧА <<<\n")
	fmt.Printf("    Task ID (Placement ID): %s\n", task.TaskID)
	fmt.Printf("    Campaign ID: %s\n", task.CampaignID)

    content := task.Creative.Content
    if content.Text != "" {
        fmt.Printf("    Текст креатива: %s\n", content.Text)
    }
	// TODO: Здесь будет ваша логика рассылки по базе пользователей.
	fmt.Println("-------------------------------------------")
}

func main() {
	apiKey := os.Getenv("ANYADS_API_KEY")
	if apiKey == "" {
		fmt.Println("Ошибка: Переменная окружения ANYADS_API_KEY не установлена.")
		return
	}

	// Инициализируем SDK с интервалом опроса в 5 минут
	err := anyads.Init(apiKey, 5*time.Minute)
	if err != nil {
		fmt.Printf("Ошибка инициализации SDK: %v\n", err)
		return
	}

	// Устанавливаем нашу функцию-обработчик
	anyads.OnBroadcastReceived(handleAdTask)

	// Запускаем фоновый опрос
	err = anyads.Start()
	if err != nil {
		fmt.Printf("Ошибка запуска SDK: %v\n", err)
		return
	}

	// Ожидаем сигнала завершения (Ctrl+C)
	fmt.Println("Клиент AnyAds SDK запущен. Ожидание рекламных задач...")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	// Корректно останавливаем SDK
	anyads.Stop()
	fmt.Println("Клиент AnyAds SDK остановлен.")
}

```

> **Верификация:** Для обработки команды верификации от модераторов, вам нужно в вашем боте поймать сообщение, начинающееся с `/verify_anyads_`, и передать его в функцию `anyads.ProcessVerificationCode(code)`.
