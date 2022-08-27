# APTHunter: Detecting Advanced Persistent Threats in Early Stages

## 1-0-Audit

To start system audit and configure audit rules. 

## 1-1-TC-DAS

Configuring Kafka for log consumption. 

## 2-LogCore

For Log parsersing, Normalization and for Causality Tracking. Output from this stage is used to generate the whole system provenance graph. 


## 3-Generate-Graph
To generate the whole system provenance graph based on the normalized log form. 

## 4-Detection-Engine
To run APTHunter's provenance queries on the whole system graph.  
