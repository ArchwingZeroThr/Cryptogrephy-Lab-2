import sys
from PyQt5.QtWidgets import QApplication,QMainWindow,QMessageBox
from PyQt5.QtGui import QFont
from window import Ui_AES  # 导入转换后的类
import SAES,Attack,SAES_2,SAES_3
from PyQt5.QtCore import QTimer

class MainWindow(QMainWindow,Ui_AES):
    def __init__(self):
        super().__init__()
        self.setupUi(self)  # 初始化 UI
        self.setFixedSize(970,720)
        self.pushButton_saes_enc.clicked.connect(self.click_button_saes_enc)
        self.pushButton_saes_dec.clicked.connect(self.click_button_saes_des)
        self.pushButton_asc_enc.clicked.connect(self.asc_enc)
        self.pushButton_asc_dec.clicked.connect(self.asc_des)
        self.pushButton_double_enc.clicked.connect(self.double_enc)
        self.pushButton_double_dec.clicked.connect(self.double_dec)
        self.pushButton_triple_enc.clicked.connect(self.triple_enc)
        self.pushButton_triple_dec.clicked.connect(self.triple_dec)
        self.pushButton_attack.clicked.connect(self.into_attack)
        self.pushButton_attack_2.setVisible(False)
        self.pushButton_attack_2.clicked.connect(self.exit_attack)
        self.pushButton_attack_3.setVisible(False)
        self.pushButton_attack_3.clicked.connect(self.calculate_key)
        self.pushButton_attack_4.clicked.connect(self.into_cbc)
        self.pushButton_attack_5.setVisible(False)
        self.pushButton_attack_5.clicked.connect(self.exit_cbc)
        self.pushButton_attack_6.setVisible(False)
        self.pushButton_attack_6.clicked.connect(self.cbc)


    #S-AES 16bits加密
    def click_button_saes_enc(self):
        input_1=self.lineEdit_input.text()
        input_key=self.lineEdit_key.text()
        if input_1 and input_key:
            if len(input_1) != 16 or len(input_key) != 16:
                QMessageBox.warning(self,'Waring','输入的密文与密钥必须为16bit')
                return
            elif all(char in '01' for char in input_key and input_1):
                final_output = SAES.s_aes_encrypt(input_1, input_key)
                self.textBrowser_output.clear()
                self.label_out.clear()
                self.label_out.setText('加密结果')
                self.label_out.setFont(QFont('Agency FB',10).setBold(True))
                self.textBrowser_output.setText(final_output)
                return
            else:
                QMessageBox.warning(self, 'Waring', '输入的密钥与密文必须为二进制')
                return
        else:
            QMessageBox.warning(self, 'Warning', '密文和密钥不能为空')
            return

    # S-AES 16bits解密
    def click_button_saes_des(self):
        input_1=self.lineEdit_input.text()
        input_key=self.lineEdit_key.text()
        if input_1 and input_key:
            if len(input_1) != 16 or len(input_key) != 16:
                QMessageBox.warning(self,'Waring','输入的密文与密钥必须为16bit')
                return
            elif all(char in '01' for char in input_key and input_1):
                final_output = SAES.s_aes_decrypt(input_1, input_key)
                self.textBrowser_output.clear()
                self.label_out.setText('解密结果')
                self.label_out.setFont(QFont('Agency FB', 10).setBold(True))
                self.textBrowser_output.setText(final_output)
                return
            else:
                QMessageBox.warning(self, 'Waring', '输入的密钥与密文必须为二进制')
                return
        else:
            QMessageBox.warning(self, 'Warning', '密文和密钥不能为空')
            return
    #ASCII码加密
    def asc_enc(self):
        try:
            input_1 = self.lineEdit_input.text()
            input_key = self.lineEdit_key.text()
            if input_1 and input_key:
                if len(input_key) != 16:
                    QMessageBox.warning(self, 'Warning', '输入的密钥必须为16位')
                    return
                else:
                    final_output = SAES.aes_encrypt(input_1, input_key)
                    if final_output is not None:
                        self.textBrowser_output.clear()
                        self.label_out.setText('ASCII加密结果')
                        self.textBrowser_output.setText(final_output)
                    else:
                        QMessageBox.information(self, 'Info', '加密失败')
                    return
            else:
                QMessageBox.warning(self, 'Warning', '密文和密钥不能为空')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'发生错误：{str(e)}')
            print(f'发生错误：{str(e)}')
    #ASCII码解密
    def asc_des(self):
        input_1 = self.lineEdit_input.text()
        input_key = self.lineEdit_key.text()
        if input_1 and input_key:
            if len(input_key) != 16:
                QMessageBox.warning(self, 'Waring', '输入的密钥必须为16位')
                return
            else:
                final_output = SAES.aes_decrypt(input_1, input_key)
                self.textBrowser_output.clear()
                self.label_out.setText('ASCII解密结果')
                # self.label_out.setFont(QFont('Agency FB', 10).setBold(True))
                self.textBrowser_output.setText(final_output)
                return
        else:
            QMessageBox.warning(self, 'Warning', '密文和密钥不能为空')
            return
    #32bits双重加密
    def double_enc(self):
        input_1 = self.lineEdit_input.text()
        input_key = self.lineEdit_key.text()
        if input_1 and input_key:
            if len(input_key) != 32:
                QMessageBox.warning(self, 'Waring', '输入的密钥必须为32bit')
                return
            else:
                final_output = SAES_2.encrypt(input_1, input_key)
                self.textBrowser_output.clear()
                self.label_out.setText('双重加密结果')
                # self.label_out.setFont(QFont('Agency FB', 10).setBold(True))
                self.textBrowser_output.setText(final_output)
                return
        else:
            QMessageBox.warning(self, 'Warning', '密文和密钥不能为空')
            return
    #32bits双重解密
    def double_dec(self):
        input_1 = self.lineEdit_input.text()
        input_key = self.lineEdit_key.text()
        if input_1 and input_key:
            if len(input_key) != 32:
                QMessageBox.warning(self, 'Waring', '输入的密钥必须为32bit')
                return
            else:
                final_output = SAES_2.decrypt(input_1, input_key)
                self.textBrowser_output.clear()
                self.label_out.setText('双重解密结果')
                # self.label_out.setFont(QFont('Agency FB', 10).setBold(True))
                self.textBrowser_output.setText(final_output)
                return
        else:
            QMessageBox.warning(self, 'Warning', '密文和密钥不能为空')
            return
    #48bits三重加密
    def triple_enc(self):
        input_1 = self.lineEdit_input.text()
        input_key = self.lineEdit_key.text()
        if input_1 and input_key:
            if len(input_key) != 48:
                QMessageBox.warning(self, 'Waring', '输入的密钥必须为48bit')
                return
            else:
                final_output = SAES_3.encrypt(input_1, input_key)
                self.textBrowser_output.clear()
                self.label_out.setText('三重加密结果')
                # self.label_out.setFont(QFont('Agency FB', 10).setBold(True))
                self.textBrowser_output.setText(final_output)
                return
        else:
            QMessageBox.warning(self, 'Warning', '密文和密钥不能为空')
            return
    #48bits三重解密
    def triple_dec(self):
        input_1 = self.lineEdit_input.text()
        input_key = self.lineEdit_key.text()
        if input_1 and input_key:
            if len(input_key) != 48:
                QMessageBox.warning(self, 'Waring', '输入的密钥为48bit')
                return
            else:
                final_output = SAES_3.decrypt(input_1, input_key)
                self.textBrowser_output.clear()
                self.label_out.setText('三重加密结果')
                # self.label_out.setFont(QFont('Agency FB', 10).setBold(True))
                self.textBrowser_output.setText(final_output)
                return
        else:
            QMessageBox.warning(self, 'Warning', '密文和密钥不能为空')
            return
    #相遇攻击求密钥
    #进入求密钥模式
    def into_attack(self):
        self.pushButton_saes_enc.setVisible(False)
        self.pushButton_saes_dec.setVisible(False)
        self.pushButton_asc_enc.setVisible(False)
        self.pushButton_asc_dec.setVisible(False)
        self.pushButton_double_enc.setVisible(False)
        self.pushButton_double_dec.setVisible(False)
        self.pushButton_triple_enc.setVisible(False)
        self.pushButton_triple_dec.setVisible(False)
        self.pushButton_attack_2.setVisible(True)
        self.pushButton_attack.setVisible(False)
        self.pushButton_attack_3.setVisible(True)
        self.pushButton_attack_4.setVisible(False)
        self.label_input.setText("明文")
        self.label_key.setText("密文")
        self.label_out.setText("解出密钥")
        self.lineEdit_key.clear()
        self.lineEdit_input.clear()
    #退出求密钥模式
    def exit_attack(self):
        self.pushButton_saes_enc.setVisible(True)
        self.pushButton_saes_dec.setVisible(True)
        self.pushButton_asc_enc.setVisible(True)
        self.pushButton_asc_dec.setVisible(True)
        self.pushButton_double_enc.setVisible(True)
        self.pushButton_double_dec.setVisible(True)
        self.pushButton_triple_enc.setVisible(True)
        self.pushButton_triple_dec.setVisible(True)
        self.pushButton_attack.setVisible(True)
        self.pushButton_attack_2.setVisible(False)
        self.pushButton_attack_3.setVisible(False)
        self.pushButton_attack_4.setVisible(True)
        self.label_input.setText("输入\n密文/明文")
        self.label_key.setText("密钥")
        self.label_out.setText("输出\n明文/密文")
        self.lineEdit_key.clear()
        self.lineEdit_input.clear()
        self.textBrowser_output.clear()
    def calculate_key(self):
        input_pla=self.lineEdit_input.text()
        input_cip=self.lineEdit_key.text()
        if input_pla and input_cip:
            QMessageBox.information(self,"info","请耐心等待，解密钥需要一些时间")
            final_out = Attack.attack(input_pla, input_cip)
            self.textBrowser_output.clear()
            self.textBrowser_output.setText(final_out)
            return
        else:
            QMessageBox.warning(self, 'Warning', '明文和密文都不能为空')
    def into_cbc(self):
        self.pushButton_saes_enc.setVisible(False)
        self.pushButton_saes_dec.setVisible(False)
        self.pushButton_asc_enc.setVisible(False)
        self.pushButton_asc_dec.setVisible(False)
        self.pushButton_double_enc.setVisible(False)
        self.pushButton_double_dec.setVisible(False)
        self.pushButton_triple_enc.setVisible(False)
        self.pushButton_triple_dec.setVisible(False)
        self.pushButton_attack.setVisible(False)
        self.pushButton_attack_4.setVisible(False)
        self.pushButton_attack_5.setVisible(True)
        self.pushButton_attack_6.setVisible(True)
        self.label_input.setText("输入明文")
        self.label_key.setText("密钥16bits")
        self.label_out.setText("输出密文")
        self.lineEdit_key.clear()
        self.lineEdit_input.clear()
    def exit_cbc(self):
        self.pushButton_saes_enc.setVisible(True)
        self.pushButton_saes_dec.setVisible(True)
        self.pushButton_asc_enc.setVisible(True)
        self.pushButton_asc_dec.setVisible(True)
        self.pushButton_double_enc.setVisible(True)
        self.pushButton_double_dec.setVisible(True)
        self.pushButton_triple_enc.setVisible(True)
        self.pushButton_triple_dec.setVisible(True)
        self.pushButton_attack.setVisible(True)
        self.pushButton_attack_4.setVisible(True)
        self.pushButton_attack_5.setVisible(False)
        self.pushButton_attack_6.setVisible(False)
        self.label_input.setText("输入\n密文/明文")
        self.label_key.setText("密钥")
        self.label_out.setText("输出\n明文/密文")
        self.lineEdit_key.clear()
        self.lineEdit_input.clear()
        self.textBrowser_output.clear()
    def cbc(self):
        input_pla = self.lineEdit_input.text()
        input_key = self.lineEdit_key.text()
        if input_pla and input_key:
            if len(input_key)==16:
                final_out=SAES.cbc_encrypt(input_pla,input_key)
                self.textBrowser_output.clear()
                self.textBrowser_output.setText(final_out)
            else:
                QMessageBox.warning(self,"Waring","密钥必须为16位")
        else:
            QMessageBox.warning(self,"Waring","明文与密钥不能为空")


#窗口显示
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()