a python netcat tool 

*it not only supports remote system-cmd exec but also dynamic python script exec

*you need setup M2Crypto python package , or you can modify source , it's easy

sclient.py usage:
        -e cmd                                  #exec system cmd
        -r remotefile [localfile=stdout]        #read file
        -w remotefile "haha"                    #write file
        -wf remotefile localfile                #write file
        -p "print 123"                          #exec python script!
        -pf localfile(1.py)                     #exec python script file!



