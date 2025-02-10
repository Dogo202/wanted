<?php

namespace src;

use yii\base\Component;
use RuntimeException;

class StreamHelper extends Component
{
    /**
     * Расширяет mediaKey до 112 байт с использованием HKDF.
     *
     * @param string $mediaKey
     * @param string $appInfo
     * @return string
     */
    public static function expandMediaKey(string $mediaKey, string $appInfo): string
    {
        return hash_hkdf('sha256', $mediaKey, 112, $appInfo);
    }

    /**
     * Шифрует данные с использованием AES-256-CBC.
     *
     * @param string $data
     * @param string $cipherKey
     * @param string $iv
     * @return string
     */
    public static function encrypt(string $data, string $cipherKey, string $iv): string
    {
        $encrypted = openssl_encrypt($data, 'aes-256-cbc', $cipherKey, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new RuntimeException('Encryption failed');
        }
        return $encrypted;
    }

    /**
     * Дешифрует данные с использованием AES-256-CBC.
     *
     * @param string $data
     * @param string $cipherKey
     * @param string $iv
     * @return string
     */
    public static function decrypt(string $data, string $cipherKey, string $iv): string
    {
        $decrypted = openssl_decrypt($data, 'aes-256-cbc', $cipherKey, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            throw new RuntimeException('Decryption failed');
        }
        return $decrypted;
    }

    /**
     * Генерирует MAC для данных.
     *
     * @param string $data
     * @param string $macKey
     * @return string
     */
    public static function generateMac(string $data, string $macKey): string
    {
        return substr(hash_hmac('sha256', $data, $macKey, true), 0, 10);
    }
}