"""*********************************************************************
get_file_path_name enable user to select a file in dialog window
and return the file path and file name

Wind 20180924
*********************************************************************"""
def IT_OS_get_file_path_name(initial_dir="\\"):
	import time,os.path, os,shutil,tkinter.filedialog
	if initial_dir[0].isalpha()==False:#Not start like c:
		initial_dir=os.getcwd()+initial_dir
	root1=tkinter.Tk()
	root1.withdraw()
	full_name=tkinter.filedialog.askopenfilename(title="Choose File",\
	initialdir=(os.path.expanduser(initial_dir)))
	root1.destroy()
	file_path=os.path.split(full_name)[0]
	file_name=os.path.split(full_name)[1]
	return([file_path,file_name])

#print (IT_OS_get_file_path_name("\\file\\msu_report"))


"""*********************************************************************
IT_OS_get_8_digit_GMT_date returns date in 8 digital format like 20181010
if need local time, replace gmttime with localtime in code
to get today, delta_day=0
to get yesterday, delta_day=-1

Wind 20181010
*********************************************************************"""
def IT_OS_get_8_digit_GMT_date(delta_day):
	import time

	year=str(time.gmtime(time.time()+24*60*60*delta_day).tm_year)
	month=str(time.gmtime(time.time()+24*60*60*delta_day).tm_mon)
	if len(month)==1:
		month="0"+month		
	day=str(time.gmtime(time.time()+24*60*60*delta_day).tm_mday)
	if len(day)==1:
		day="0"+day		
	timestamp=year+month+day
	return(timestamp)
	
print(IT_OS_get_8_digit_GMT_date(-1))
