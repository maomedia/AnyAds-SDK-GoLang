package anyads

import "time"

var defaultSDK *PollingSDK

// Init инициализирует глобальный экземпляр SDK.
func Init(apiKey string, interval time.Duration) error {
	if defaultSDK != nil {
		return nil // Уже инициализирован
	}
	
	sdk, err := NewClient(apiKey, interval)
	if err != nil {
		return err
	}
	defaultSDK = sdk
	return nil
}

// Start запускает глобальный SDK.
func Start() error {
	if defaultSDK == nil {
		return ErrSDKNotInitialized
	}
	return defaultSDK.Start()
}

// OnBroadcastReceived устанавливает коллбэк для глобального SDK.
func OnBroadcastReceived(handler BroadcastHandler) {
	if defaultSDK != nil {
		defaultSDK.OnBroadcastReceived(handler)
	}
}

// Stop останавливает глобальный SDK.
func Stop() {
	if defaultSDK != nil {
		defaultSDK.Stop()
	}
}