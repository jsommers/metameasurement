import sys
import os
from matplotlib import pyplot as plt

def readstuff(fname):
    data = {
        'intendedpps':[],
        'actualpps':[],
        'idlemean':[],
        'idlestdev':[],
        'rttmean':[],
        'rttstdev':[],
    }
    mapper = ( (0,int,'intendedpps'),
               (1,float,'actualpps'),
               (2,float,'idlemean'),
               (3,float,'idlestdev'),
               (7,float,'rttmean'),
               (8,float,'rttstdev'),
            )
    with open(fname) as inf:
        for line in inf:
            fields = line.split()
            for idx,xtype,name in mapper:
                data[name].append(xtype(fields[idx]))
        return data

def plotstuff():
    pib_data = readstuff('pib_send_microbench.txt') 
    pi3_data = readstuff('pi3_send_microbench.txt') 

    fig = plt.figure(figsize=(6,4))

    ax1 = fig.add_subplot(111, xlabel='Intended packet rate (pps)',
        ylabel='Achieved packet rate (pps)')
    ax1.plot(pib_data['intendedpps'], pib_data['actualpps'], linestyle='-', color='k', label='Pi 1 model B pps')
    ax1.plot(pi3_data['intendedpps'], pi3_data['actualpps'], linestyle='-.', color='grey', label='Pi 3 model B pps')
    ax1.set_xlim(0,200)
    ax1.set_ylim(0,200)
    ax1.legend(loc='upper right', fontsize=8)

    ax2 = ax1.twinx()
    ax2.plot(pib_data['intendedpps'], pib_data['idlemean'], linestyle='--', color='blue', label='Pi 1 model B CPU idle')
    ax2.plot(pi3_data['intendedpps'], pi3_data['idlemean'], linestyle=':', color='green', label='Pi 3 model B CPU idle')
    ax2.set_ylabel('CPU idle (%)')
    ax2.set_ylim(0,100)
    ax2.legend(loc='upper left', fontsize=8)

    fig.tight_layout()
    plt.savefig('send_microbench.png')

def main(argv):
    if not os.path.isfile('pib_send_microbench.txt') or \
       not os.path.isfile('pi3_send_microbench.txt'): 
       print("microbench files not found?")
    plotstuff()

if __name__ == '__main__':
    main(sys.argv)
