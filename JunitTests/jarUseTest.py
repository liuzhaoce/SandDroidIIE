import  subprocess
import json
print"hello"
p = subprocess.Popen(['java', '-jar', '/home/mindmac/workspace/SandDroidIIE/resources/tools/androidmd5.jar', '-f', '/home/mindmac/workspace/SandDroidIIEWeb/samples/upload/1B7C9B1B67E51D406051729AE1E984E2.apk'],stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)
stdout, stderr = p.communicate()
print "stdout:",stdout
result = json.loads(stdout)
#print(result.key())
print(result['virusName'])
print(result['code'])
