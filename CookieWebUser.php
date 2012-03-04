<?php
/**
 * Yii cookie-based WebUser component
 *
 * PHP version 5
 *
 * @category Auth
 * @package  Auth_User
 * @author   Andryeyev Sergey <funcod3r@gmail.com>
 * @license  https://github.com/andser/CookieWebUser/blob/master/LICENSE.md  New BSD License
 * @link     https://github.com/andser/CookieWebUser
 */

/**
 * CookieWebUser class
 *
 * @category Auth
 * @package  Auth_User
 * @author   Andryeyev Sergey <funcod3r@gmail.com>
 * @license  https://github.com/andser/CookieWebUser/blob/master/LICENSE.md  New BSD License
 * @link     https://github.com/andser/CookieWebUser
 */
class CookieWebUser extends CApplicationComponent implements IWebUser
{
    const VERSION = '1.0';

    /**
     * @var string|array the URL for login. If using array, the first element
     * should be the route to the login action, and the rest name-value pairs are
     * GET parameters to construct the login URL (e.g. array('/site/login')).
     * If this property is null, a 403 HTTP exception will be raised instead.
     * @see CController::createUrl
     */
    public $loginUrl = array('/site/login');

    /**
     * @var string secret key for cookie validation
     */
    public $secretKey = 'vdnSM1dFWzNxvrsT';

    /**
     * @var string guest user name
     */
    public $guestName = 'Guest';

    /**
     * @var bool true is user is guest
     */
    public $isGuest = true;

    /**
     * @var string cookie key
     */
    public $cookieName = 'user';

    /**
     * @var string cookie domain
     */
    public $cookieDomain = '';

    /**
     * @var array internal user data
     */
    private $_userData = array();

    /**
     * @var array accesses for AuthManager
     */
    private $_access = array();

    /**
     * Initializes the application component.
     * This method overrides the parent implementation by performing
     * cookie-based authentication.
     *
     * @return void
     */
    public function init()
    {
        parent::init();
        $cookie = $this->getCookie();
        if ($cookie !== false) {
            $this->_userData = $cookie;
        } else {
            Yii::app()->request->cookies->remove($this->cookieName);
        }
    }

    /**
     * Login function
     *
     * @param CUserIdentity $identity user identity
     * @param int           $duration duration of cookie
     *
     * @return void
     */
    public function login($identity, $duration)
    {
        $userId = $identity->getId();
        $name = $identity->getName();

        // @todo Implement an ability to get/set persistent states
        $states = $identity->getPersistentStates();
        if ($this->beforeLogin($userId, $states, false)) {
            $cookieData = array(
                'id' => $userId,
                'name' => $name,
            );
            $this->_userData = $cookieData;
            $this->setCookie($cookieData, $duration);
            $this->isGuest = false;
            $this->afterLogin(false);
        }
    }

    /**
     * Logs out the current user. This will remove auth cookie.
     *
     * @return void
     */
    public function logout()
    {
        if ($this->beforeLogout()) {
            /**
             * This not working (when using $this->cookieDomain):
             * Yii::app()->getRequest()->getCookies()->remove($this->cookieName);
             * But this - works perfect:
             */
            if (version_compare(PHP_VERSION, '5.2.0', '>=')) {
                setcookie(
                    $this->cookieName, null, 0, "/", $this->cookieDomain, null, null
                );
            } else {
                setcookie(
                    $this->cookieName, null, 0, "/", $this->cookieDomain, null
                );
            }
            unset(Yii::app()->request->cookies[$this->cookieName]);
            unset($_COOKIE[$this->cookieName]);
            setcookie($this->cookieName, null, -1);
            $this->isGuest = true;
            $this->afterLogout();
        }
    }

    /**
     * This method validates cookie value.
     * $value must be a string
     * $value must have 4 string entities separated by '/' symbol:
     * - format version;
     * - effective data;
     * - timestamp of cookie creation;
     * - checksum;
     * Timestamp must be numeric.
     * Length of checksum must be 40 symbols.
     * Effective data must be encoded by base64_encode function.
     * Decoded effective data must be an associative array.
     * Checksum must be identical to generateChecksum() function result.
     *
     * @param string $value cookie value
     *
     * @return bool if cookie value is valid - return true, else - return false
     */
    public function validateCookieValue($value)
    {
        if (!is_string($value)) {
            return false;
        }
        $a_value = explode('/', $value);
        if (!is_array($a_value) || count($a_value) != 4) {
            return false;
        }
        list($ver, $data, $timestamp, $checksum) = $a_value;
        if ($ver != self::VERSION) {
            return false;
        }
        if (!is_numeric($timestamp)) {
            return false;
        }
        if (strlen($checksum) != 40) {
            return false;
        }
        if (!is_array(json_decode(base64_decode($data), true))) {
            return false;
        }
        $genChecksum = $this->generateChecksum(
            $ver . '/' . $data . '/' . $timestamp, $timestamp
        );
        if ($genChecksum !== $checksum) {
            return false;
        }

        return true;
    }

    /**
     * Sets cookie
     *
     * @param array $data     user data
     * @param int   $duration cookie lifetime
     *
     * @return CHttpCookie
     */
    protected function setCookie($data, $duration = 0)
    {
        $t = time();
        $value = self::VERSION . '/' . base64_encode(json_encode($data)) . '/' . $t;
        $finalValue = $value . '/' . $this->generateChecksum($value, $t);
        $cookie = new CHttpCookie($this->cookieName, $finalValue);
        $cookie->domain = $this->cookieDomain;
        $cookie->path = "/";
        if ($duration > 0) {
            $cookie->expire = time() + $duration;
        }
        Yii::app()->request->cookies[$this->cookieName] = $cookie;

        return $cookie;
    }

    /**
     * Gets cookie
     *
     * @return bool|array
     */
    protected function getCookie()
    {
        $cookies = Yii::app()->request->cookies;
        if (isset($cookies[$this->cookieName])
            && $cookies[$this->cookieName]->value != ''
        ) {
            $value = Yii::app()->request->cookies[$this->cookieName]->value;
            if ($this->validateCookieValue($value)) {
                $this->isGuest = false;
                $arrValue = explode("/", $value);
                list($ver, $data, $timestamp, $checksum) = $arrValue;
                return json_decode(base64_decode($data), true);
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Generates checksum
     *
     * @param string $value     data that must be hashed
     * @param int    $timestamp timestamp
     *
     * @return string
     */
    public function generateChecksum($value, $timestamp)
    {
        return sha1(md5(md5($value . $timestamp . $this->secretKey)));
    }

    /**
     * Returns a value that uniquely represents the identity.
     *
     * @return mixed a value that uniquely represents the identity
     * (e.g. primary key value).
     */
    public function getId()
    {
        return ($id = $this->getUserData('id')) ? $id : null;
    }

    /**
     * Sets a value that uniquely represents the identity.
     *
     * @param mixed $value the unique identifier for the user.
     * If null, it means the user is a guest.
     *
     * @return void
     */
    public function setId($value)
    {
        $this->setUserData('id', $value);
    }

    /**
     * Returns the display name for the identity (e.g. username).
     *
     * @return string the display name for the identity.
     */
    public function getName()
    {
        return ($name = $this->getUserData('name')) ? $name : $this->guestName;
    }

    /**
     * Sets the unique identifier for the user (e.g. username).
     *
     * @param string $value the user name.
     *
     * @see getName
     * @return void
     */
    public function setName($value)
    {
        $this->setUserData('name', $value);
    }

    /**
     * This method is called before logging in a user.
     * You may override this method to provide additional security check.
     * For example, when the login is cookie-based, you may want to verify
     * that the user ID together with a random token in the states can be found
     * in the database. This will prevent hackers from faking arbitrary
     * identity cookies even if they crack down the server private key.
     *
     * @param mixed   $id         the user ID. This is the same as returned
     * by {@link getId()}.
     * @param array   $states     a set of name-value pairs that are provided
     * by the user identity.
     * @param boolean $fromCookie whether the login is based on cookie
     *
     * @return boolean whether the user should be logged in
     */
    protected function beforeLogin($id, $states, $fromCookie)
    {
        return true;
    }

    /**
     * This method is called after the user is successfully logged in.
     * You may override this method to do some postprocessing (e.g. log the user
     * login IP and time; load the user permission information).
     *
     * @param boolean $fromCookie whether the login is based on cookie.
     *
     * @return void
     */
    protected function afterLogin($fromCookie)
    {
    }

    /**
     * This method is invoked when calling {@link logout} to log out a user.
     * If this method return false, the logout action will be cancelled.
     * You may override this method to provide additional check before
     * logging out a user.
     *
     * @return boolean whether to log out the user
     */
    protected function beforeLogout()
    {
        return true;
    }

    /**
     * This method is invoked right after a user is logged out.
     * You may override this method to do some extra cleanup work for the user.
     *
     * @return void
     */
    protected function afterLogout()
    {
    }

    /**
     * Returns the URL that the user should be redirected to after successful login.
     * This property is usually used by the login action. If the login is successful,
     * the action should read this property and use it to redirect the user browser.
     *
     * @return string the URL that the user should be redirected to after login.
     * @see loginRequired
     */
    public function getReturnUrl()
    {
        return Yii::app()->getRequest()->getScriptUrl();
    }

    /**
     * PHP magic method.
     * This method is overriden so that persistent states can be accessed
     * like properties.
     *
     * @param string $name property name
     *
     * @return mixed property value
     */
    public function __get($name)
    {
        if ($this->getUserData($name)) {
            return $this->getUserData($name);
        } else {
            return parent::__get($name);
        }
    }

    /**
     * Sets user data
     *
     * @param string $name  name for user data key
     * @param string $value value for user data key
     *
     * @return void
     */
    protected function setUserData($name, $value)
    {
        $this->_userData[$name] = $value;
    }

    /**
     * Returns user data array
     *
     * @param string $name name of user data key
     *
     * @return array|bool
     */
    protected function getUserData($name)
    {
        return (isset($this->_userData[$name])) ? $this->_userData[$name] : false;
    }

    /**
     * Returns a value indicating whether the user is a guest (not authenticated).
     *
     * @return boolean whether the user is a guest (not authenticated)
     */
    public function getIsGuest()
    {
        return $this->isGuest;
    }

    /**
     * Performs access check for this user.
     *
     * @param string  $operation    the name of the operation that need access check.
     * @param array   $params       name-value pairs that would be passed
     * to business rules associated with the tasks and roles assigned to the user.
     * @param boolean $allowCaching whether to allow caching the result of access
     * check. This parameter has been available since version 1.0.5.
     * When this parameter is true (default), if the access check of an operation
     * was performed before, its result will be directly returned when calling this
     * method to check the same operation. If this parameter is false, this method
     * will always call {@link CAuthManager::checkAccess} to obtain the up-to-date
     * access result.
     * Note that this caching is effective only within the same request.
     *
     * @return boolean whether the operations can be performed by this user.
     */
    public function checkAccess($operation, $params = array(), $allowCaching = true)
    {
        if ($allowCaching && $params === array()
            && isset($this->_access[$operation])
        ) {
            return $this->_access[$operation];
        } else {
            $authMan = Yii::app()->getAuthManager();
            return $this->_access[$operation] = $authMan->checkAccess(
                $operation, $this->getId(), $params
            );
        }
    }

    /**
     * Redirects the user browser to the login page.
     * Before the redirection, the current URL (if it's not an AJAX url) will be
     * kept in {@link returnUrl} so that the user browser may be redirected back
     * to the current page after successful login. Make sure you set {@link loginUrl}
     * so that the user browser can be redirected to the specified login URL after
     * calling this method.
     * After calling this method, the current request processing will be terminated.
     *
     * @return void
     */
    public function loginRequired()
    {
        $app = Yii::app();
        $request = $app->getRequest();

        if (($url = $this->loginUrl) !== null) {
            if (is_array($url)) {
                $route = isset($url[0]) ? $url[0] : $app->defaultController;
                $url = $app->createUrl($route, array_splice($url, 1));
            }
            $request->redirect($url);
        } else {
            throw new CHttpException(403, Yii::t('yii', 'Login Required'));
        }
    }
}
