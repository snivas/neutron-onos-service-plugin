# neutron-onos-service-plugin
ONOSFP is a Neutron Service Plugin that interacts with ONOS SDN Controller through REST to CRUD Flows in to the switches that are controlled by ONOS

About:

     ONOSFP is a openstack neutron service plugin that interfaces with ONOS SDN Controller through REST interface to CRUD flow rules in to the switches.
     Another objective is to have a step-by-step example for creating a complete neutron service plugin.
     
Pre-Requisites

    * Openstack (I have used all-in one setup[not devstack])
    * ONOS SDN Controller
    * Python skills
    
Flow of Implementation (Easy First Approach :))

    * Start from neutron client - Implement code at Neutron client
    * Test if neutronclient is sending data in expected url
    * Implement extension and service plugin at Neutron Server (skip onos interfacing and DB access this time)
    * Test if the flow of message is complete - i.e. 
              neutronclient->generates request to the endpoint exposed by newly implemented neutron Extension
              The incoming request from the client is composed by neutron plugin
              Neutron plugin uses driver module to make a simple restcall and returns a result
    - Branch v0.1 has a snapshot of the above implementation
    * Install ONOS
    * Implement complete Driver and DB operation modules.
    - Master has the implementation of all  mentioned
    
Artifacts

    Neutron Server
        - extensions
        - services
              |-onosfp
                |-db
                  |-onosfp_db.py
                |-driver
                  |-onos_driver.py
                |-onosfp_plugin.py
                
    Neutron Client
        |-neutron
        |    |-v2_0
        |       |-onosfp
        |          |- onosfp.py
        |
        |-v2_0
        |   |- client.py
        |- shell.py
        
Currently working on to make full CRUD. Many of the values are hardcoded as it will be easy to understand.
            
