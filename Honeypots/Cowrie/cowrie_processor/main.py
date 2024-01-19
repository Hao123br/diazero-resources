import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
from logging.handlers import SysLogHandler
from log_processor import LogProcessor  # Importa a classe LogProcessor do outro arquivo

# Configurar logging para console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console_logger = logging.getLogger('console')

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, processor, logger, syslog_logger):
        self.processor = processor
        self.logger = logger
        self.syslog_logger = syslog_logger
        self.last_position = 0

    def on_modified(self, event):
        if not event.is_directory:
            self.logger.info(f"Arquivo modificado detectado: {event.src_path}")
            with open(event.src_path, "r") as file:
                file.seek(0, 2)  # Vai para o final do arquivo
                file_size = file.tell()

                if file_size < self.last_position:
                    # O arquivo foi truncado ou recriado, resetar a posição
                    self.last_position = 0
                    self.logger.info("O arquivo de log foi truncado ou recriado. Resetando a posição de leitura.")

                # Volta para a última posição conhecida
                file.seek(self.last_position)

                for line in file:
                    processed_event = self.processor.process_log_line(line)
                    if processed_event:
                        self.logger.info(f"Linha processada: {processed_event}")
                        self.syslog_logger.info(processed_event)

                # Atualiza a última posição conhecida
                self.last_position = file.tell()

if __name__ == "__main__":
    script_name = 'cowrie_processor'
    processor = LogProcessor(script_name)

    # Configurar o logger para enviar para o syslog remoto
    syslog_logger = logging.getLogger(script_name)
    syslog_logger.setLevel(logging.INFO)
    syslog_handler = SysLogHandler(address=('syslog', 514))
    syslog_logger.addHandler(syslog_handler)

    # Configurar o observer para monitorar o arquivo de log
    path_to_watch = '/home/cowrie/cowrie/var/log/cowrie/cowrie.log'
    event_handler = LogFileHandler(processor, console_logger, syslog_logger)
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=False)
    observer.start()

    console_logger.info("Monitoramento de arquivo iniciado.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        console_logger.info("Monitoramento de arquivo interrompido.")
    observer.join()
    console_logger.info("Script finalizado.")