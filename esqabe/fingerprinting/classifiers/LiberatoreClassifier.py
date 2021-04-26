# This is a Python framework to compliment "Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis Countermeasures Fail".
# Copyright (C) 2012  Kevin P. Dyer (kpdyer.com)
# See LICENSE for more details.
# Adapted by Isaac Meers (isaacmeers.be)


from .. import arffWriter
from . import wekaAPI

class LiberatoreClassifier:
    @staticmethod
    def traceToInstance( trace ):
        instance = trace.get_histogram()
        instance['class'] = str(trace.get_id())
        return instance
    
    @staticmethod
    def classify( runID, trainingSet, testingSet ):
        [trainingFile,testingFile] = arffWriter.writeArffFiles( runID, trainingSet, testingSet )
        return wekaAPI.execute( trainingFile, testingFile, "weka.classifiers.bayes.NaiveBayes", ['-K'] )
