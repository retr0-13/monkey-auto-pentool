from monkey_island.cc.environment import Environment


class PasswordEnvironment(Environment):
    _credentials_required = True

    def get_auth_users(self):
        if self._is_registered():
            return self._config.get_users()
        else:
            return []
