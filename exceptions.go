package anyads

import "errors"

var (
	ErrInvalidAPIKey      = errors.New("неверный формат API ключа, он должен начинаться с 'anyads_'")
	ErrSDKNotInitialized  = errors.New("SDK не был инициализирован, вызовите anyads.Init()")
	ErrHandlerNotSet      = errors.New("обработчик (BroadcastHandler) не был установлен")
	ErrPollingAlreadyRun  = errors.New("фоновый опрос уже запущен")
)