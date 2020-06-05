#!/usr/bin/python3
import sys
import hmac
import hashlib
import time
import argparse
import subprocess
import requests

# ---------------
#  CONFIGURATION
# ---------------
APP_TOKEN = ""
FREEBOX_IP = "212.27.38.253"
CHECK_IPS = ["8.8.8.8", "1.1.1.1"]
WHITELIST_IPS = [FREEBOX_IP]


class FreeboxReboot:
    APP_CONFIG = {
        "app_id": "fr.umeda.reboot_utility",
        "app_name": "Freebox Reboot Utility",
        "app_version": "1.0.0",
        "device_name": "Freebox Client",
    }

    CONFIGURATION_MESSAGE = """
Copiez ce token dans la variable APP_TOKEN du fichier {} :

{}

!!! ATTENTION !!!
Vous devez maintenant autoriser l'application à redémarrer la Freebox :

- Connectez-vous à l'interface d'administration sur http://{}/
- Cliquez sur le menu Free, puis "Paramètres" et "Paramètres de la Freebox"
- Ouvrez "Gestion des accès", puis l'onglet "Applications"
- Cliquez sur le bouton éditer sur la ligne "Freebox Reboot Utility"
- Activez "Modification des réglages de la Freebox"

Vérifiez ensuite la configuration à l'aide de la commande :

{} verify
"""

    def __init__(self, app_token, freebox_ip, check_ips, whitelist_ips):
        self._app_token = app_token
        self._freebox_ip = freebox_ip
        self._check_ips = check_ips
        self._whitelist_ips = whitelist_ips

        self._base_url = None
        self._login_info = None

    def _req(self, url, json=None, auth=False):
        # Fetch configuration
        if self._base_url is None:
            # Fetch configuration
            configuration = requests.get(
                "http://{}/api_version".format(self._freebox_ip)
            ).json()
            api_base_url = configuration["api_base_url"]
            port = configuration["https_port"]
            api_version = configuration["api_version"].split(".")[0]

            if configuration["https_available"]:
                self._base_url = "https://{}:{}{}v{}/".format(
                    self._freebox_ip, port, api_base_url, api_version
                )
            else:
                self._base_url = "http://{}{}v{}/".format(
                    self._freebox_ip, api_base_url, api_version
                )

        # Handle authentification
        headers = {}
        if auth:
            if self._login_info is None:
                self._login()

            headers["X-Fbx-App-Auth"] = self._login_info["session_token"]

        # Build and launch request
        # FIXME SSL Validation
        if json is None:
            req = requests.get(self._base_url + url, verify=False, headers=headers)
        else:
            req = requests.post(
                self._base_url + url, json=json, verify=False, headers=headers
            )

        # Check result
        req.raise_for_status()
        data = req.json()
        if not data["success"]:
            raise Exception("Error")

        # Return result
        return data.get("result")

    def _ping(self, ip):
        return (
            subprocess.call(
                ["ping", "-c", "1", "-W", "1", ip],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
            == 0
        )

    def _login(self):
        # Logging in
        challenge = self._req("login/")["challenge"]
        token_b = bytes(self._app_token, "latin-1")
        challenge_b = bytes(challenge, "latin-1")
        password = hmac.new(token_b, challenge_b, hashlib.sha1).hexdigest()

        self._login_info = self._req(
            "login/session/",
            json={
                "app_id": FreeboxReboot.APP_CONFIG["app_id"],
                "app_version": FreeboxReboot.APP_CONFIG["app_version"],
                "password": password,
            },
        )

    def _verify_app_token(self):
        if self._app_token == "":
            raise Exception(
                "APP_TOKEN n'est pas définie.\nVeuillez lancer la commande suivante et suivre les instructions :\n\n{} register".format(
                    sys.argv[0]
                )
            )

    def logout(self):
        if self._login_info is None:
            return

        self._req("login/logout/", json={}, auth=True)

    def register(self):
        """ Registers the application on FreeboxOS
        """
        # Fetch challenge
        data = self._req("login/authorize", json=FreeboxReboot.APP_CONFIG)
        app_token = data["app_token"]
        track_id = data["track_id"]

        # Wait until user validates the app
        print("Veuillez autoriser l'application sur l'écran de la Freebox...")
        status = "pending"
        while status == "pending":
            time.sleep(1)
            status = self._req("login/authorize/{}".format(track_id))["status"]

        # Check result
        if status != "granted":
            raise Exception("Impossible d'autoriser l'application : {}".format(status))

        print(
            FreeboxReboot.CONFIGURATION_MESSAGE.format(
                sys.argv[0], app_token, self._freebox_ip, sys.argv[0]
            )
        )

    def check(self):
        # Check user configured the token
        self._verify_app_token()

        # Ping whitelist
        for ip in self._whitelist_ips:
            if not self._ping(ip):
                raise Exception(
                    'L\'adresse IP sur liste blanche "{}" ne répond pas.'.format(ip)
                )

        # Ping check ips
        for ip in self._check_ips:
            if self._ping(ip):
                return  # All good !

        # Internet is down
        print(
            "Impossible de contacter les adresses IP {}...".format(
                ", ".join(self._check_ips)
            )
        )
        self.reboot()

    def reboot(self):
        print("Lancement du redémarrage de la Freebox...")

        self._req("system/reboot", json={}, auth=True)

    def verify(self):
        self._verify_app_token()
        self._login()

        if not self._login_info["permissions"]["settings"]:
            raise Exception("Les permissions de l'application ne sont pas correctes.")

        print("OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Outil pour redémarrer la Freebox lorsqu'une déconnexion est détectée."
    )
    parser.set_defaults(func="check")

    subparsers = parser.add_subparsers(title="Commandes")
    parser_register = subparsers.add_parser(
        "register", help="Enregistre l'application sur FreeboxOS"
    )
    parser_register.set_defaults(func="register")

    parser_verify = subparsers.add_parser(
        "verify", help="Vérifie la configuration du script"
    )
    parser_verify.set_defaults(func="verify")

    parser_reboot = subparsers.add_parser("reboot", help="Redémarre la Freebox")
    parser_reboot.set_defaults(func="reboot")

    parser_check = subparsers.add_parser(
        "check", help="Vérifie l'accès à internet et redémarre la Freebox si nécessaire"
    )
    parser_check.set_defaults(func="check")

    args = parser.parse_args()

    # Run the command
    client = FreeboxReboot(
        app_token=APP_TOKEN,
        freebox_ip=FREEBOX_IP,
        check_ips=CHECK_IPS,
        whitelist_ips=WHITELIST_IPS,
    )
    try:
        func = getattr(client, args.func)
        func()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print("ERREUR")
        print(str(e))

        exit(1)
    finally:
        client.logout()
