import os
from datetime import datetime
import hashlib
import AES
start = 512
path='E:'
class Header:
    def __init__(self):
        self.Signature = b'.HPQ'  
        self.SizeOfVolume = b''  
        self.PassWord = b''   

class DoiTuong:
    def __init__(self):
        self.status = b''       # 0    1   byte  
        self.ma = b''           # 1    10  byte
        self.ho_ten = b''       # 11   32  byte
        self.ngay_sinh = b''    # 43   4   byte
        self.ngay_tham_gia = b''# 47   4   byte
        self.so_dt = b''        # 51   16  byte
        self.so_cccd = b''      # 67   16  byte
        self.ngay_tao = b''     # 83   4   byte
        self.passHash = b''     # 87   32  byte
   
def chooseSizeOfVolume():
    sizes = {
    1: 512*100,         # 51200  byte
    2: 512*200,         # 102400 byte
    3: 512*300          # 204800 byte
    }   
    while True:
        choice = int(input("Chọn dung lượng lưu trữ (1: 512  byte, 2: 1025 byte, 3: 2048 byte): "))
        if choice in sizes:
            return sizes[choice]
        else:
            print("Vui lòng chỉ chọn từ 1 đến 3. Thử lại.")

def is_all_zeros(byte_string):
    return all(byte == 0 for byte in byte_string)
    
    
def padding_temp(string_to_insert,num):
    if len(string_to_insert) >= num:
        return string_to_insert[:num]  # Trả về chuỗi chỉ chứa num ký tự đầu tiên nếu chuỗi đã đủ num ký tự hoặc hơn

    remaining_chars = num - len(string_to_insert)  # Số ký tự cần chèn
    additional_chars = b'\0' * remaining_chars  # Ký tự để chèn vào chuỗi

    return string_to_insert + additional_chars

def createNewVolume(path):# Tạo mới file .HQP và hỏi mật khẩu
    header = Header()
    header.SizeOfVolume = chooseSizeOfVolume().to_bytes(4, byteorder='big')
    option = input("1: Đặt mật khẩu\n2: bỏ qua\n")
    if option == '1':
        temp, header.PassWord = createNewPass()
        print("Tạo mật khẩu thành công")
    else:
        print("Không có mật khẩu")
    dataBlock = padding_temp(padding_temp(header.Signature + header.SizeOfVolume, 16) + header.PassWord,512)
    
    if os.path.exists(path +"/.HPQ"):
        print("Đã tồn tại. Vui lòng chọn đường dẫn khác.")
    else:
        with open(path + "/.HPQ", "wb") as file:
            file.seek(int.from_bytes(header.SizeOfVolume, byteorder='big') - 1)
            file.write(b'\0')
            file.close()
    with open(path + "/.HPQ", "rb+") as file:
        file.write(dataBlock)
    return header

def readVolume(path):
    with open(path + "/.HPQ", "rb+") as file:
        data = file.read(512)
    header = Header()
    if header.Signature == data[:4]:
        print("Volume hợp lệ")
    else:
        print("Không phải định dạng .HPQ, không đọc được!!!")
        return 1
    header.SizeOfVolume = data[4:8]
    header.PassWord = data[16:48]
    if (is_all_zeros(header.PassWord)):
        return header
    else:
        while(True):
            Pass=input("Nhập mật khẩu để truy cập Volume: ")
            if(AES.sha256_hash_string(Pass) != header.PassWord):
                print("Sai mật khẩu!")
                return 0
            else:
                return header
# mã hóa và giải mã toàn bộ file       
def decVolume(path, header):
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(512)
        data = file.read()
        file.seek(512)
        file.write(AES.dec(padding(header.PassWord, 32),data))
        
def encVolume(path, header):
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(512)
        data = file.read()
        file.seek(512)
        file.write(AES.enc(padding(header.PassWord, 32),data))

def padding(string_to_insert, num):
    if len(string_to_insert) >= num:
        return string_to_insert[:num]  # Trả về chuỗi chỉ chứa num ký tự đầu tiên nếu chuỗi đã đủ num ký tự hoặc hơn

    remaining_chars = num - len(string_to_insert)  # Số ký tự cần chèn
    additional_chars = b'\x00' * remaining_chars  # Chèn ký tự 'X' vào chuỗi

    return string_to_insert.encode('utf-8') + additional_chars   

def createNewPass():
    while True:
        newPass = input("Nhập password phải nhỏ hơn 16 kí tự(Enter bỏ qua): ")
        if len(newPass) < 16:
            return newPass,AES.sha256_hash_string(newPass)  
        if len(newPass) == 0:
            return 0,0

def is_all_zeros(byte_string):
    return all(byte == 0 for byte in byte_string)

def convert_date_to_hex(date):
    day_hex = hex(int(date.strftime('%d')))[2:].zfill(2)
    month_hex = hex(int(date.strftime('%m')))[2:].zfill(2)
    year_hex = hex(int(date.strftime('%Y')))[2:].zfill(4)
    return f"{day_hex}{month_hex}{year_hex}"

def decode_byte_to_date(byte_string):
    if len(byte_string) < 4:
        return "Chuỗi byte không đủ độ dài để chuyển đổi"

    ngay_byte = byte_string[0]
    thang_byte = byte_string[1]
    nam_byte = int.from_bytes(byte_string[2:], byteorder='big')

    return f"{ngay_byte}/{thang_byte}/{nam_byte}"
#hàm nhập 1 đối tượng mới
def nhap_doituong():
    hoc_sinh_moi = DoiTuong()
    hoc_sinh_moi.status = input("Nhập Trạng thái(2: HS, 3: GV): ")
    hoc_sinh_moi.ma = input("Nhập mã: ")
    hoc_sinh_moi.ho_ten = input("Nhập họ và tên: ")
    
    ngay_sinh = list(map(int, input("Nhập ngày sinh (ngày tháng năm - cách nhau bởi dấu cách): ").split()))
    date = convert_date_to_hex(datetime(ngay_sinh[2], ngay_sinh[1], ngay_sinh[0]))
    hoc_sinh_moi.ngay_sinh=bytes.fromhex(date)
    
    ngay_tham_gia = list(map(int, input("Nhập ngày tham gia (ngày tháng năm - cách nhau bởi dấu cách): ").split()))
    date = convert_date_to_hex(datetime(ngay_tham_gia[2], ngay_tham_gia[1], ngay_tham_gia[0]))
    hoc_sinh_moi.ngay_tham_gia=bytes.fromhex(date)
    
    hoc_sinh_moi.so_dt = input("Nhập số điện thoại: ")
    hoc_sinh_moi.so_cccd = input("Nhập số CCCD: ")
    
    ngay_tao_today = datetime.now().strftime("%d %m %Y")
    date = convert_date_to_hex(datetime.strptime(ngay_tao_today, "%d %m %Y"))
    hoc_sinh_moi.ngay_tao = bytes.fromhex(date)
    
    passWord, hoc_sinh_moi.passHash = createNewPass()
    if len(passWord) != 0:
        hoc_sinh_moi.so_dt = AES.enc(padding(passWord,16),hoc_sinh_moi.so_dt.encode())
        hoc_sinh_moi.so_cccd = AES.enc(padding(passWord,16),hoc_sinh_moi.so_cccd.encode())
    # password = input("Nhập password: ")
    # hoc_sinh_moi.passHash = hashlib.sha256(password.encode()).hexdigest()
    return hoc_sinh_moi
#Hàm viết đối tượng vào file
def writeDoiTuong(object,path,start=512): #Viet 128byte 1 lan
    
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(start) #0h
        file.write(padding(object.status.encode(),1))    
            
        file.seek(start +1) #19h
        file.write(padding(object.ma,10))  
        
        file.seek(start +11 ) #23h   
        file.write(padding(object.ho_ten,32))   
        
        file.seek(start +43) #25h  
        file.write(padding(object.ngay_sinh,4))        
        
        file.seek(start +47) #25h  
        file.write(padding(object.ngay_tham_gia,4))
        
        file.seek(start + 51) #25h 
        if (is_all_zeros(object.passHash)): 
            file.seek(start + 51) #25h    
            file.write(padding(object.so_dt,16))
            file.seek(start + 67) #25h  
            file.write(padding(object.so_cccd,16))
        else:
            file.seek(start + 51) #25h 
            file.write(object.so_dt)
            file.seek(start + 67) #25h
            file.write(object.so_cccd)
        
        file.seek(start + 83) #25h  
        file.write(padding(object.ngay_tao,4))
       
        file.seek(start + 87)
        file.write(object.passHash)
#ham để đọc 1 đối tượng từ HxD
# def read_1doituong(object,path,start=512):
#     with open(path + "/.HPQ", "rb+") as file:
#         file.seek(start)
#         data=file.read(128)
#         object.status = data[:1].replace(b'\x00', b'')
#         object.ma = data[1:10].replace(b'\x00', b'')
#         object.ho_ten = data[11:42].replace(b'\x00', b'')
#         ngay_sinh = data[43:47].replace(b'\x00', b'')
#         object.ngay_sinh = decode_byte_to_date(ngay_sinh).encode('utf-8')
        
#         ngay_tham_gia = data[47:51].replace(b'\x00', b'')
#         object.ngay_tham_gia = decode_byte_to_date(ngay_tham_gia).encode('utf-8')
        
#         object.so_dt = data [51:67].replace(b'\x00', b'')
#         object.so_cccd = data[67:83].replace(b'\x00', b'')
        
#         ngay_tao = data [83:87].replace(b'\x00', b'')
#         object.ngay_tao = decode_byte_to_date(ngay_tao).encode('utf-8')
        
#         object.passHash = data [88:119].replace(b'\x00', b'')
#     return object
#hàm đọc tất cả các đối tượng đang được lưu trong file
def read_all_Object(path):
    gv = []
    hs = []    
    del_gv = []
    del_hs = []  
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(512)       
        while True:  
            data = file.read(128)              
            
            temp = DoiTuong()           
                
            temp.status = data[:1].replace(b'\x00', b'')
            temp.ma = data[1:10].replace(b'\x00', b'')
            temp.ho_ten = data[11:42].replace(b'\x00', b'')
            ngay_sinh = data[43:47].replace(b'\x00', b'')
            temp.ngay_sinh = decode_byte_to_date(ngay_sinh).encode('utf-8')
            
            ngay_tham_gia = data[47:51].replace(b'\x00', b'')
            temp.ngay_tham_gia = decode_byte_to_date(ngay_tham_gia).encode('utf-8')
            
            temp.so_dt = data [51:67].replace(b'\x00', b'')
            temp.so_cccd = data[68:83].replace(b'\x00', b'')
            
            ngay_tao = data [83:87].replace(b'\x00', b'')
            temp.ngay_tao = decode_byte_to_date(ngay_tao).encode('utf-8')
            
            temp.passHash = data [87:119].replace(b'\x00', b'')
            if (temp.status == b'2'):    
                hs.append(temp)
            elif (temp.status == b'3'):
                gv.append(temp)           
            elif (temp.status == b'0'):    
                del_hs.append(temp)
            elif (temp.status == b'1'):
                del_gv.append(temp)   
            
            # Assuming the end condition, you might have a specific criteria to stop the loop
            if not data:
                break
            
    return hs,gv,del_gv ,del_hs #hàm trả ra danh sách gồm GV, HS và những GV, HS đã xóa tạm
#hàm tiếp vị trí trống tiếp theo hoặc vị trí có status 0 hoặc 1
# read(128) check có phải zero ko , có thì return pos ,
#           check bit đầu có dạng 0 hay 1 gì ko , nếu có thì return pos 
#           còn ko có data thì return -1 
def find_available_pos(path):
    pos = 0
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(512)  
        while True:
            data = file.read(128)  # Hàm Read() chưa được định nghĩa ở đây
                       
            if is_all_zeros(data):
                return pos
            elif data[:1] in (b'0', b'1'):
                return pos
            elif not data : 
                print('Khong con trong')
                return -1
            pos += 1
#hàm add để write đối tượng lên HxD            
def add(path,start=512):
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(512)               
        pos =  find_available_pos(path)  
        temp = start + pos*128     
        if (pos >= 0):
            object = nhap_doituong()
            writeDoiTuong(object,path,temp)           
#hàm để in ra list 
def print_info(object):
    for index, obj in enumerate(object, start=1):
        print(f"Index: {index}")
        print(f"Status: {obj.status}")
        print(f"Ma: {obj.ma}")
        print(f"Ho ten: {obj.ho_ten}")
        print(f"Ngay sinh: {obj.ngay_sinh}")
        print(f"Ngay tham gia: {obj.ngay_tham_gia}")
        print(f"so DT: {obj.so_dt}")
        print(f"so CCCD: {obj.so_cccd}")
        print(f"Ngay tao: {obj.ngay_tao}")
        print(f"Password: {obj.passHash}")
        print()
#hàm xóa tạm thời hoặc xóa vĩnh viến 1 đối tượng        
def delete_object(path, start=512):
    ma_nhap = input('Nhập mã: ')
    block_size = 128
    
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(start)
        while True:
            current_position = file.tell()
            data = file.read(block_size)
            
            if not data:
                print('Mã không tồn tại')
                os.system('pause')
                return
            
            ma_temp = data[1:10].replace(b'\x00', b'').decode('utf-8')
            pass_temp = data[87:119].replace(b'\x00', b'')
            
            if ma_temp == ma_nhap:
                _, hash_pass = createNewPass()
                if pass_temp == hash_pass:
                    choice = input('Xoá hoàn toàn (Y/N): ')
                    if choice == 'Y':
                        file.seek(current_position)
                        file.write(b'\x00' * block_size)
                        file.truncate()
                        print('Đã xoá hoàn toàn')
                        os.system('pause')
                        return
                    elif choice == 'N':
                        current_status = data[:1].replace(b'\x00', b'').decode('utf-8')
                        if current_status in ('0', '1'):
                            continue
                        new_status = '0' if current_status == '2' else '1'
                        file.seek(current_position)
                        file.write(new_status.encode())
                        print('Đã xoá tạm')
                        os.system('pause')
                        return
                    else:
                        print('Xoá không thành công')
                        os.system('pause')
                        return
                else:
                    print('Sai mật khẩu')
                    os.system('pause')
                    return

            file.seek(current_position + block_size)
#Chinh sửa 1 đối tượng  
def edit_object(path, start=512):
    ma_nhap = input('Nhập mã: ')
    block_size = 128
    
    with open(path + "/.HPQ", "r+b") as file:
        file.seek(start)
        while True:
            current_position = file.tell()
            data = file.read(block_size)
            
            if not data:
                return
            
            current_status = data[:1].replace(b'\x00', b'').decode('utf-8')
            ma = data[1:10].replace(b'\x00', b'').decode('utf-8')
            pass_temp = data[87:119].replace(b'\x00', b'')
            
            if ma == ma_nhap:
                if current_status == '0' or current_status == '1':
                    print('')
                    os.system('pause')
                    return
                password, hash_pass = createNewPass()
                if pass_temp == hash_pass:
                    print('Chọn thông tin cần đổi')
                    print('1. Ngày sinh')
                    print('2. Ngày tham gia')
                    print('3. SĐT')
                    print('4. Mật khẩu')
                    print('0. Thoát')
                    choice = int(input("Nhập lựa chọn: "))
                    if choice == 0:
                        return
                    elif choice == 1:
                        temp = data[43:47].replace(b'\x00', b'')
                        temp2 = decode_byte_to_date(temp).encode('utf-8')
                        print(f'Ngày sinh cũ: {temp2}')
                        ngay_sinh = list(map(int, input("Nhập ngày sinh mới (ngày tháng năm - cách nhau bởi dấu cách): ").split()))
                        date = convert_date_to_hex(datetime(ngay_sinh[2], ngay_sinh[1], ngay_sinh[0]))
                        
                        file.seek(current_position + 43)
                        file.write(padding(bytes.fromhex(date), 4))
                    elif choice == 2:
                        temp = data[47:51].replace(b'\x00', b'')
                        temp2 = decode_byte_to_date(temp).encode('utf-8')
                        print(f'Ngày tham gia cũ: {temp2}')
                        ngay_tham_gia = list(map(int, input("Nhập ngày tham gia mới (ngày tháng năm - cách nhau bởi dấu cách): ").split()))
                        date = convert_date_to_hex(datetime(ngay_tham_gia[2], ngay_tham_gia[1], ngay_tham_gia[0]))
                        
                        file.seek(current_position + 47)
                        file.write(padding(bytes.fromhex(date), 4))
                    elif choice == 3:
                        newSDT = input("Nhập số điện thoại mới: ")
                        file.seek(current_position + 51)
                        file.write(AES.enc(padding(password, 16), padding(newSDT, 16)))
                        
                    elif choice == 4:
                        file.seek(current_position + 51)
                        sdt = AES.dec(padding(password, 16), file.read(16))
                        file.seek(current_position + 67)
                        cccd = AES.dec(padding(password, 16), file.read(16))
                        new_pass, new_hash_pass = createNewPass()
                        file.seek(current_position + 87)
                        file.write(new_hash_pass)
                        file.seek(current_position + 51)
                        file.write(AES.enc(padding(new_pass, 16), sdt))
                        file.seek(current_position + 67)
                        file.write(AES.enc(padding(new_pass, 16), cccd))
                    
                    return
                
            file.seek(current_position + block_size)
        
def print_menu():
    hs,gv,del_gv,del_hs=read_all_Object(path)
    while True:
        os.system('cls')
        print('In dãy phần tử')
        print('1. HS')
        print('2. GV')
        print('3. HS xoá tạm')
        print('4. GV xoá tạm')
        print('0. Thoát')
        choice = int(input("Lựa chọn: "))
        if choice == 0:
            return
        elif choice == 1:
            print_info(hs)
            os.system('pause')
        elif choice == 2:
            print_info(gv)
            os.system('pause')
        elif choice == 3:
            print_info(del_hs)
            os.system('pause')
        elif choice == 4:
            print_info(del_gv)
            os.system('pause')
        else:
            print('Lựa chọn không tồn tại')
            os.system('pause')
        
def submenu(path, header):
    while True:
        os.system('cls')
        print('File 2 dãy phần tử')
        print('1. In')
        print('2. Thêm')
        print('3. Xoá')
        print('4. Sửa')
        print('0. Thoát')
        choice = int(input("Lựa chọn: "))
        if choice == 0:
            encVolume(path, header)
            return 0
        elif choice == 1:
            print_menu()
        elif choice == 2:
            add(path, start)
        elif choice == 3:
            delete_object(path, start)
        elif choice == 4:
            edit_object(path, start)
        
def mainmenu():
    while True:
        os.system('cls')
        print("______________ .HPQ VOLUME _______________")
        print("1: Nhập đường dẫn chứa volume để mở volume")
        print("2: Tạo mới volume")
        print("0: Thoát chương trình")

        choice = input("Nhập lựa chọn của bạn: ")

        if choice == "1":
            path = input("Nhập đường dẫn chứa volume: ")
            header = readVolume(path)
            decVolume(path, header)
            submenu(path, header)

        elif choice == "2":
            path = input("Nhập đường dẫn mới: ")
            header = createNewVolume(path)
            submenu(path, header)

        elif choice == "0":
            print("Thoát chương trình.")
            break  # Kết thúc chương trình nếu người dùng chọn thoát

        else:
            print("Lựa chọn không hợp lệ. Vui lòng chọn lại.")

mainmenu()