import sys
  
# setting path
sys.path.append('/Users/quaiddelacluyse/repositories/terry')

from classes import *
from utils import *

utils.verbose_logging = True

config_files = RemoteConfiguration('team-info', 'gitlab.com/5tag3/team_info.git', 'quaid.delacluyse', '')