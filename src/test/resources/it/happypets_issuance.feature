Feature: An Happypets User get a credentials and uses it to access packetdelivery.

  Scenario: An admin user gets a credential from HappyPets, using the OIDC4VCI flow.
    Given An application provides access to PacketDelivery.
    And The HappyPets issuer is ready to provide credentials.
    And The policies are properly setup.
    When The admin user requests a credentials offer from HappyPets.
    And The users uses the offer to receive a credential.
    And The user authenticates with the same-device flow.
    Then The user can access PacketDeliveries backend.