<?php

namespace tests;

use src\DecryptionStream;
use src\EncryptionStream;
use GuzzleHttp\Psr7\Stream;
use PHPUnit\Framework\TestCase;

class StreamTest extends TestCase
{
    private static $mediaTypeAppInfo = [
        'IMAGE' => 'WhatsApp Image Keys',
        'VIDEO' => 'WhatsApp Video Keys',
        'AUDIO' => 'WhatsApp Audio Keys',
        'DOCUMENT' => 'WhatsApp Document Keys',
    ];

    /**
     * Тестирование шифрования и дешифрования.
     *
     * @dataProvider mediaTypeProvider
     */
    public function testEncryptionDecryption($mediaType)
    {
        $originalFile = __DIR__ . "/../samples/{$mediaType}.original";
        $keyFile = __DIR__ . "/../samples/{$mediaType}.key";
        $encryptedFile = __DIR__ . "/../samples/{$mediaType}.encrypted";

        // Чтение оригинального файла
        $originalData = file_get_contents($originalFile);
        $this->assertNotEmpty($originalData, 'Original file is empty');

        // Чтение ключа
        $mediaKey = file_get_contents($keyFile);
        $this->assertNotEmpty($mediaKey, 'Key file is empty');

        // Чтение зашифрованного файла
        $encryptedData = file_get_contents($encryptedFile);
        $this->assertNotEmpty($encryptedData, 'Encrypted file is empty');

        // Шифрование
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $originalData);
        rewind($stream);

        $psrStream = new Stream($stream);
        $encryptionStream = new EncryptionStream($psrStream, $mediaKey, self::$mediaTypeAppInfo[$mediaType]);

        $encryptedResult = $encryptionStream->getContents();

        // Проверка, что зашифрованные данные совпадают с эталоном
        $this->assertEquals(
            hash('sha256', $encryptedData),
            hash('sha256', $encryptedResult),
            'Encryption result hash does not match the sample'
        );
        if (hash('sha256', $encryptedData) === hash('sha256', $encryptedResult)) {
            echo "Encryption for {$mediaType} matches the sample.\n";
        }

        // Дешифрование
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $encryptedData);
        rewind($stream);

        $psrStream = new Stream($stream);
        $decryptionStream = new DecryptionStream($psrStream, $mediaKey, self::$mediaTypeAppInfo[$mediaType]);

        $decryptedResult = $decryptionStream->getContents();

        // Проверка, что дешифрованные данные совпадают с оригиналом
        $this->assertEquals(
            hash('sha256', $originalData),
            hash('sha256', $decryptedResult),
            'Decryption result hash does not match the original'
        );
        if (hash('sha256', $originalData) === hash('sha256', $decryptedResult)) {
            echo "Decryption for {$mediaType} matches the original.\n";
        }
    }

    /**
     * Провайдер данных для тестирования разных типов медиа.
     *
     * @return array
     */
    public static function mediaTypeProvider()
    {
        return [
            ['IMAGE'],
            ['VIDEO'],
            ['AUDIO']
            // Добавьте другие типы, если есть файлы для них
        ];
    }
}