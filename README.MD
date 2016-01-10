# EasyRouter

## Introduction

This is a basic PHP router mainly created for learning purposes. This works well for when you don't want the router
function of your application tied so tightly to the rest of your application. It provides easy to read code as well.

Supports PHP 7.

If you have any suggestions or bug fixes please feel free to let me know.

Specify the controller and the controller method to call when a route is matched using addRoute().

To match wild cards use the following phrases in your route path:
* (any) - Matches any combination of upper case/lower case letters and numbers.
* (int) - Matches only integers.
* (abc) - Matches any combination of upper case/lower case letters.

## Example Usage

#### Typical Use of Easy Router
```php
include (__DIR__ . '/vendor/autoload.php');

use \NickStuer\EasyRouter\Route as Route;

$routeManager = new \NickStuer\EasyRouter\RouteManager();
$dispatcher = new \NickStuer\EasyRouter\Dispatcher($routeManager);

$routeManager->addRoute(new Route('get', '/', 'ControllerToCall@methodToCall'));
$routeManager->addRoute(new Route('get', '/about', 'PagesController@showAbout'));
$routeManager->addRoute(new Route('get', '/contact', 'PagesController@showContact'));
$routeManager->addRoute(new Route('get', '/profile/(abc)', 'ProfileController@showProfile'));

try {
    $dispatcher->dispatch();
} catch (\NickStuer\EasyRouter\Exceptions\RouteNotFoundException $e) {
    echo "Route Not Found - 404";
    exit;
} catch (\NickStuer\EasyRouter\Exceptions\MethodNotAllowedException $e) {
    echo "Method Not Allowed - 405";
    exit;
}

$routeInfo = $dispatcher->getMatchedRoute();

/**
 * It's recommended that you use a DI container to create the controller class to
 * automatically insert the required dependencies.
 */
$controller = new $routeInfo['controller'];
$method = $routeInfo['method'];
$controller->$method($routeInfo['variables']);
```

## License

Easy Router is licensed under the [MIT license](http://opensource.org/licenses/MIT)