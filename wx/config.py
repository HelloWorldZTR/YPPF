from utils.config import Config, LazySetting
from boot.config import ROOT_CONFIG

__all__ = ['miniAPP_config']

class MiniAPPConfig(Config):
    app_id = LazySetting('app_id', type=str)
    app_secret = LazySetting('app_secret', type=str)


miniAPP_config = MiniAPPConfig(ROOT_CONFIG, 'miniapp')