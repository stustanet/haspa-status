import argparse
import logging
import os
import json
import time
from dataclasses import dataclass
from pathlib import Path

from paho.mqtt.client import Client as PahoMqttClient


TEMPLATE_PATH = Path(os.environ.get("TEMPLATE_PATH", "templates"))
OUTPUT_PATH = Path(os.environ.get("OUTPUT_PATH", "html"))


@dataclass
class Config:
    debug: bool
    mqtt_host: str
    mqtt_port: int
    mqtt_username: str
    mqtt_password: str
    template_path: Path
    output_path: Path
    use_tls: bool


class HaspaStatus:
    """
    A simplified hauptbahnhof client that is able to connect to a remote mqtt
    with username password and certificates
    """
    def __init__(self, config: Config):
        logformat = '%(asctime)s | %(name)s | %(levelname)5s | %(message)s'
        logging.basicConfig(format=logformat)
        self.log = logging.getLogger(__name__)
        self.config = config
        if config.debug:
            self.log.setLevel(logging.DEBUG)
        else:
            self.log.setLevel(logging.INFO)

        self.subscriptions = {
            '/haspa/status': self.command_state
        }

        self.mqtt = PahoMqttClient()
        self.mqtt.enable_logger(self.log)
        self.mqtt.on_message = self.on_message
        self.mqtt.on_connect = self.on_connect

        if config.use_tls:
            self.mqtt.tls_set()

        self.mqtt.username_pw_set(username=config.mqtt_username, password=config.mqtt_password)

    def command_state(self, client, userdata, mqttmsg):
        """ /haspa/status change detected """
        del client, userdata
        message = json.loads(mqttmsg.payload.decode('utf-8'))
        self.log.debug(f"Received: {message}")
        if 'haspa' in message:
            if message['haspa'] in ['open', 'offen', 'auf']:
                self.set_state(True)
                pass
            elif message['haspa'] in ['close', 'zu', 'closed']:
                self.set_state(False)
                pass
            else:
                self.log.warning(f"Haspa state undetermined: {message['haspa']}")
        else:
            self.log.warning("Invalid Message received")

    def set_state(self, is_open):
        """
        Export the current haspa state to the website

        The templates and the update procedure have been designed by pt, I do not want to
        Change any old and glorious routines!
        """
        for template in TEMPLATE_PATH.glob('*.tpl'):
            outfile = OUTPUT_PATH / template.stem
            with open(str(template), 'r') as orig:
                content = orig.read()
                content = content.replace('#state#',
                                          "offen" if is_open else "geschlossen")
                content = content.replace('#last_update#',
                                          time.strftime("%a, %d %b %Y %H:%M:%S"))
                with open(str(outfile), 'w') as new:
                    new.write(content)

    def on_message(self, client, userdata, msg):
        """
        A message was received. push it back towards the async context
        """
        self.log.warning("Unhandled message has arrived: %s %s %s", client, userdata, msg)

    def on_connect(self, client, userdata, flags, returncode):
        """ After a successfull connection the topics are set and subscribed """
        del client, userdata
        if returncode == 0:
            self.mqtt.subscribe([(topic, 0) for topic in self.subscriptions])

            if 'session present' not in flags or flags['session present'] == 0:
                # If we have a new session
                for topic, callback in self.subscriptions.items():
                    if callback:
                        self.mqtt.message_callback_add(topic, callback)
        else:
            try:
                msg = {
                    0: "Connection successful",
                    1: "Incorrect Protocol Version",
                    2: "Invalid client identifier",
                    3: "Server unavailable",
                    4: "Bad username or password",
                    5: "Not authorized",
                }[returncode]
            except KeyError:
                msg = "Unknown error occured: " + returncode
            self.log.warning(f"Connection refused: {msg}")

    def publish(self, topic, data):
        """ Publish a message """
        self.mqtt.publish(topic, data)

    def start(self):
        """ Connect and start the mqtt machine """
        self.mqtt.connect(self.config.mqtt_host, port=self.config.mqtt_port)
        self.log.info("Successfully connected to %s", self.config.mqtt_host)

        self.mqtt.loop_forever()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mqtt-host", type=str, default="knecht.stusta.de")
    parser.add_argument("--mqtt-port", type=int, default=8883)
    parser.add_argument("--mqtt-username", type=str, required=True)
    parser.add_argument("--mqtt-password", type=str, required=True)
    parser.add_argument("--template-path", type=str, default="templates")
    parser.add_argument("--output-path", type=str, default="html")
    parser.add_argument("--use-tls", action="store_true")
    parser.add_argument("--debug", action="store_true")

    return parser.parse_args()


def main():
    args = parse_args()
    config = Config(
        mqtt_host=args.mqtt_host,
        mqtt_port=args.mqtt_port,
        mqtt_username=args.mqtt_username,
        mqtt_password=args.mqtt_password,
        template_path=args.template_path,
        output_path=args.output_path,
        debug=args.debug,
        use_tls=args.use_tls,
    )
    status = HaspaStatus(config)
    status.start()


if __name__ == "__main__":
    main()
