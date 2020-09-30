import uuid
from xml.dom import minidom
import time
def get_mac():
        mac=uuid.UUID(int = uuid.getnode()).hex[-12:].upper()
        return mac

print (get_mac())
print (time.time())

doc = minidom.parse("statuc_info.xml")
root = doc.documentElement

sensitiveAPI = root.getElementByTagName("sensitiveAPIs")

