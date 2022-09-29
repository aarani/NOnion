namespace NOnion

type RelayIntroduceStatus =
    | Success = 0us
    | Failure = 1us
    | BadMessageFormat = 2us
    | RelayFailed = 3us
