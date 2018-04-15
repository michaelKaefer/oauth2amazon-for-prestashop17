```php
<?php

require 'vendor/autoload.php';


$amazonProvider = new MichaelKaefer\OAuth2AmazonForPrestashop17\MichaelKaefer\OAuth2\Client\Provider\Amazon([
    'clientId'          => 'x',
    'clientSecret'      => 'x',
    'redirectUri'       => 'x'
]);

// Get authorization code
if (!isset($_GET['code'])) {
    // Get authorization URL
    $options = [
        'scope' => ['profile', 'postal_code', 'payments:widget', 'payments:shipping_address', 'payments:billing_address']
    ];
    $authorizationUrl = $amazonProvider->getAuthorizationUrl($options);

    // Get state and store it to the session
    $_SESSION['oauth2state'] = $amazonProvider->getState();

    // Redirect user to authorization URL
    header('Location: ' . $authorizationUrl);
    exit;
// Check for errors
} elseif (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }
    exit('Invalid state');
} else {
    // Get access token
    try {
        $accessToken = $amazonProvider->getAccessToken(
            'authorization_code',
            [
                'code' => $_GET['code']
            ]
        );
    } catch (\MichaelKaefer\OAuth2ClientForPrestashop17\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
        exit($e->getMessage());
    }

    // Get resource owner
    try {
        $resourceOwner = $amazonProvider->getResourceOwner($accessToken);
    } catch (\MichaelKaefer\OAuth2ClientForPrestashop17\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
        exit($e->getMessage());
    }

    // Now you can store the results to session ...
    $_SESSION['accessToken'] = $accessToken;
    $_SESSION['resourceOwner'] = $resourceOwner;

    var_dump($accessToken, $resourceOwner->toArray());
    var_dump($resourceOwner->toArray());
    var_dump(get_class($resourceOwner));
    print_r($resourceOwner);
}
```