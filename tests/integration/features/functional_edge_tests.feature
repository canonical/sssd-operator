Feature: Functional edge tests
  Functional tests for the edge risk level


  @functional @edge
  Scenario: Deploy the SSSD charm with a principal charm
    Given I pack a 'sssd' charm
    And I add model 'sssd'
    And I switch to model 'sssd'
    And I deploy 'sssd' from a local charm located at 'sssd.charm'
    And I deploy 'ubuntu' on base 'ubuntu@26.04' from channel 'latest/stable'
    And I integrate 'sssd:juju-info' with 'ubuntu:juju-info'
    Then all agents are 'idle' in model 'sssd'
    And the workload status for app 'sssd' is 'waiting'
    And the workload status message for app 'sssd' is 'Waiting for integrations: [`ldap`]'
  Scenario: Integrate SSSD with an LDAP server
    Given 'sssd' is deployed
    And I add model 'ldap'
    And I set 'cloudinit-userdata' for model 'ldap' to 'tests/integration/assets/openldap-cloud-init.yaml'
    And I deploy 'ubuntu' in model 'ldap' on base 'ubuntu@26.04' from channel 'latest/stable' with name 'openldap'
    And I deploy 'ldap-integrator' in model 'sssd' on base 'ubuntu@24.04' from channel 'latest/stable'
    And I configure 'ldap-integrator' with data from 'openldap'
    And I integrate 'sssd:ldap' with 'ldap-integrator:ldap'
    Then all agents are 'idle' in models 'sssd' and 'ldap'
    And the workload status for app 'sssd' is 'active'
    And the workload status message for app 'sssd' is ''
  Scenario: Access a remote user
    Given 'sssd' is deployed
    And 'sssd' is integrated with 'ldap-integrator'
    When I execute 'getent passwd nucci' on unit 'sssd/0'
    Then the output should be 'nucci:*:10000:10000:nucci:/home/nucci:/bin/bash'
