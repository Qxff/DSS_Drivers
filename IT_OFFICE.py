"""*********************************************************************
merge_csv_to_xls enable user to merge multiple csv with same name header
to one xls file.
f is the number to cut file header from rear
c is the number of charactor from the rear of filename for sheet name
if source file name is ABC20180913.csv,ABC20180914.csv f=-2,c=-4
                       ABC201809
merged filename will be ABC281809,sheet name will be 0913&0914

Wind 20180924
*********************************************************************"""
def IT_OFFICE_merge_csv_to_xls(filename_cut,sheetname_lenth,initial_dir="\\"):
	from IT_OS import IT_OS_get_file_path_name
	print(filename_cut)
	print(sheetname_lenth)
	import xlwt,os,csv
	import csv 
	fpfn= IT_OS_get_file_path_name(initial_dir)
	file_path=fpfn[0]
	file_name=fpfn[1]
	suffix_lenth=len('.csv')
	
	if os.path.splitext(file_name)[1] != '.csv':
		print("Error,only csv file is supported.")
		return()
	file_header=file_name[:filename_cut-suffix_lenth]
	print("file_header")
	print(file_header)
	csv_file_list = []
	files = os.listdir(file_path)  
	for filename in files:  
		if os.path.splitext(filename)[1] == '.csv':
			if file_header in os.path.splitext(filename)[0]:
				csv_file_list.append(filename)

	print (csv_file_list)
	output_file_name=file_header+".xls"
	book = xlwt.Workbook()
	
	for file in csv_file_list:
		f = open(file_path+"\\"+file, 'r')
		csvreader = csv.reader(f)
		final_list = list(csvreader)
		sheet = book.add_sheet(file[(sheetname_lenth-suffix_lenth):-4])
		row = 0
		for entry in final_list:
			column= 0
			for item in entry:
				sheet.write(row,column,item)
				if sheet.col(column).width < (len(item)+1)*256:
					sheet.col(column).width=(len(item)+1)*256
				column+=1
			row+=1
	book.save(file_path+"\\"+output_file_name)
	fp=file_path.replace("/","\\")
	os.system("explorer.exe %s" % fp)
	
IT_OFFICE_merge_csv_to_xls(-2,-4)
