### 1.FFI

PHP>=7.4

ffi.enable=true或者reload

extension=ffi

1. FFI:cdef

```php
<?php
    $ffi = FFI:cdef("int system(const char *command);");
	$ffi->system("whoami");
?>
```

