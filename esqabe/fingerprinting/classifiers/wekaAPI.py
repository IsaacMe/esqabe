# This is a Python framework to compliment "Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis Countermeasures Fail".
# Copyright (C) 2012  Kevin P. Dyer (kpdyer.com)
# See LICENSE for more details.
# Adapted by Isaac Meers (isaacmeers.be)

import subprocess
from .. import config


def execute( trainingFile, testingFile, classifier, args ):
    myArgs = ["java",
        "-Xmx" + str(config.JVM_MEMORY_SIZE),
        "-classpath", '$CLASSPATH:'+config.WEKA_JAR,
        classifier,
        "-t", trainingFile,
        "-T", testingFile,
        '-v',
        '-classifications','weka.classifiers.evaluation.output.prediction.CSV'
        ]

    for arg in args:
        myArgs.append( arg )

    pp = subprocess.Popen(' '.join(myArgs), shell=True, stdout=subprocess.PIPE)

    answers = []
    parsing = False
    for line in pp.stdout:
        line = line.rstrip()

        if parsing:
            if line == b'':
                break
            lineBits = line.split(b',')
            actualClass = lineBits[1].split(b':')[1]
            predictedClass = lineBits[2].split(b':')[1]
            answers.append([actualClass, predictedClass])

        if line == b'inst#,actual,predicted,error,prediction':
            parsing = True

    return answers
