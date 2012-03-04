CookieWebUser Yii Component
===========================

CookieWebUser is a Yii component that using cookie only store for user auth info. It
doesn't use server-side store (memcache, $_SESSION etc). This component can be used
in highload projects.

Requirements
------------

Yii Framework 1.x and above.

Usage
-----

- Add CookieWebUser.php to protected/components.
- Add this code to 'user' component section in protected/config/main.php:

~~~
'components' => array(
    'user' => array(
        'class' => 'CookieWebUser',
        'secretKey' => 'secret key',
        'cookieName' => 'cookie name',
        'cookieDomain' => 'cookie domain',
    ),
~~~

- You can use code from http://www.yiiframework.com/doc/guide/1.1/en/topics.auth
to implement user authentication.

WARNING!!! Persistent states and flash messages not implemented yet.

License
-------

Yeeki is licensed under New BSD license. That allows proprietary use, and for
the software released under the license to be incorporated into proprietary
products. Works based on the material may be released under a proprietary license
or as closed source software. It is possible for something to be distributed
with the BSD License and some other license to apply as well.

Credits
-------

- Initial code and ideas: Sergey Andryeyev, @andser.
