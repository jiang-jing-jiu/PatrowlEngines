# -*- coding: utf-8 -*-
"""
Nessus API Tests
"""

import sys 
sys.path.append("..") 

import ness6rest
import requests

# api_akey='ce3d25f85470bcfc536b1843971e3a444e6cddef80c52b26371bc7d27272b76a',
# api_skey='fc945fee48552d599e43c30e8a4ac9c0f80441e4bf53144c75493c54b57ce375',

if __name__ == "__main__":

    # ness6rest.Scanner在初始化时会登录获取token
    # nessscan = ness6rest.Scanner(
    #             url="https://192.168.112.160:8834",
    #             login='Nessus',
    #             password='Nessus',                
    #             insecure=True)
    
    nessscan = ness6rest.Scanner(
                url="https://192.168.112.160:8834",
                api_akey="275beb85a16910fa2b90d9cb1ed512ed830e86d791538e49b7753669188ff43d",
                api_skey="ef7e9179ec8d59ce903c138f4b5dc372db2c1ab91bb386299bf4a263975a1cd1",               
                insecure=True)
    # print(nessscan.res)
    # nessscan.action(action="permissions/scanner", method="GET")
    print(nessscan.__dict__)
    # for i in range(50000):
    #     nessscan._login(login='Nessus', password='Nessus')
 
    print("\n============\n")

    # destroy session
    # nessscan.logout()
    # print("destroy session")
    # print(nessscan.res)
    # nessscan.scan_delete(name='[TO] Nessus Scan - 49 (1642927057)')

    

   
