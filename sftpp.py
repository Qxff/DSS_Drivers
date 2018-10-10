"""*******************************************************************************************************

This script provide SFTP function to download or upload specified file or all file under specified directory
1. sftp_upload(host,port,username,password,local,remote)
2. sftp_download(host,port,username,password,local,remote)


Author: Wind Wang
Version: v1.0 2018.08.24

*******************************************************************************************************"""

# coding: utf-8
#!/usr/bin/python
import paramiko
import os
import platform
import stat

import paramiko
import os
def sftp_upload(host,port,username,password,local,remote):
  sf = paramiko.Transport((host,port))
  sf.connect(username = username,password = password)
  sftp = paramiko.SFTPClient.from_transport(sf)
  try:
    if os.path.isdir(local):#判断本地参数是目录还是文件
      for f in os.listdir(local):#遍历本地目录
        sftp.put(os.path.join(local+f),os.path.join(remote+f))#上传目录中的文件
    else:
      sftp.put(local,remote)#上传文件
  except Exception as e:
    print('upload exception:',e)
  sf.close()
  
#如果remote,local都是文件夹,下载所有文件.或者都是文件,指定下载  
def sftp_download(host,port,username,password,local,remote):
	sf = paramiko.Transport((host,port))
	sf.connect(username = username,password = password)
	sftp = paramiko.SFTPClient.from_transport(sf)
	try:
		if os.path.isdir(local):#判断本地参数是目录还是文件
			print("dir is local")
			for f in sftp.listdir(remote):#遍历远程目录
				print(f)
				sftp.get(os.path.join(remote+f),os.path.join(local+f))#下载目录中文件
				#sftp.get('.kshrc',os.path.join(local+f))#下载目录中文件
		else:
			sftp.get(remote,local)#下载文件
	except Exception as e:
		print('download exception:',e)
	sf.close()

#host='10.162.28.182'
#port = 22 
#username='g707414'
#password='#Bisctac6'
#local = 'C:\\sftptest\\test'#本地文件或目录，与远程一致，当前为windows目录格式，window目录中间需要使用双斜线

#remote = '/home/g707414/'#远程文件或目录，与本地一致，当前为linux目录格式,取远程目录下所有文件
#remote = '/home/g707414/diameter-dsc.xml'#远程文件或目录，与本地一致，当前为linux目录格式

#sftp_upload(host,port,username,password,local,remote)#上传
#sftp_download(host,port,username,password,local,remote)#下载
