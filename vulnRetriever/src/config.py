import configparser

def get_config(section):
    config = configparser.ConfigParser()
    config.read('config/vulnRetriever.ini')
    return dict(config.items(section))