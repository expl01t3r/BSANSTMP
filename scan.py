#coding: utf-8
print('''
                                                                     
 _|_|_|          _|_|_|        _|_|        _|      _|        _|_|_|  
 _|    _|      _|            _|    _|      _|_|    _|      _|        
 _|_|_|          _|_|        _|_|_|_|      _|  _|  _|        _|_|    
 _|    _|            _|      _|    _|      _|    _|_|            _|  
 _|_|_|    _|  _|_|_|    _|  _|    _|  _|  _|      _|  _|  _|_|_|    

         Break Security - Automated Network Scanner
''')
import nmap
import argparse
nscan = nmap.PortScanner()
op = argparse.ArgumentParser()
op.add_argument('--alvo', action = 'store', dest = 'alvo', required = False, help = 'Digite o IP do alvo', nargs = '+')
op.add_argument('--porta', action = 'store', dest = 'porta', required = False, help = 'Digite a(s) porta(s) que serão escaneadas', default = '0-65535')
porta = []
nome = []
ver = []

ps = op.parse_args()
print('[+] Inicando escaneamento\n')
#ps.alvo = ''.join((x+' ' for x in ps.alvo))

result = nscan.scan('192.168.254.250',ps.porta,'-A')#str(ps.alvo), ps.porta)
for alvo in result['scan']:
    print('Resultados para o alvo: {alvo}\nNome do Computador: {pcnome}\nSistema Operacional: {so}\nIP: {ip}\nMAC: {mac}\nTécnica de escaneamento: {tecscan}\n' .format(alvo = alvo,
    pcnome = result['scan'][alvo]['hostname'], so = result['scan'][alvo]['osmatch'][0]['name'], ip = result['scan'][alvo]['addresses']['ipv4'],
    mac = result['scan'][alvo]['addresses']['mac'], tecscan = result['nmap']['scaninfo']['tcp']['method']))
    for x in result['scan'][alvo]['tcp']:
        print('Porta: {porta}\nEstado: {estado}\nNome do Serviço: {nome}\nver do Serviço: {versao}\nInformações Extras: {extra}\n{leponto}'.format(
            porta = x, estado = result['scan'][alvo]['tcp'][x]['state'], nome = result['scan'][alvo]['tcp'][x]['name'], versao = result['scan'][alvo]['tcp'][x]['version'],
            extra = result['scan'][alvo]['tcp'][x]['extrainfo'], leponto = ('-'*20)+'\n'))
        porta.append(x)
        nome.append(result['scan'][alvo]['tcp'][x]['name'])
        ver.append(result['scan'][alvo]['tcp'][x]['version'])
