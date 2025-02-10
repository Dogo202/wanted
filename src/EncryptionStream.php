<?php

namespace omponents;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

class EncryptionStream implements StreamInterface
{
    private $stream;
    private $cipherKey;
    private $iv;
    private $macKey;
    private $buffer = '';
    private $eof = false;

    public function __construct(StreamInterface $stream, string $mediaKey, string $appInfo)
    {
        $this->stream = $stream;
        $mediaKeyExpanded = StreamHelper::expandMediaKey($mediaKey, $appInfo);
        $this->iv = substr($mediaKeyExpanded, 0, 16);
        $this->cipherKey = substr($mediaKeyExpanded, 16, 32);
        $this->macKey = substr($mediaKeyExpanded, 48, 32);
    }

    public function read($length): string
    {
        $data = $this->stream->read($length);
        if ($data === '') {
            $this->eof = true;
            return '';
        }

        $this->buffer .= $data;
        if (strlen($this->buffer) < $length) {
            return '';
        }

        $encrypted = StreamHelper::encrypt($this->buffer, $this->cipherKey, $this->iv);
        $mac = StreamHelper::generateMac($this->iv . $encrypted, $this->macKey);

        $this->buffer = '';
        return $encrypted . $mac;
    }

    public function getSize(): ?int
    {
        return $this->stream->getSize();
    }

    public function isWritable(): bool
    {
        return false; // Поток только для чтения
    }

    public function tell(): int
    {
        return $this->stream->tell();
    }

    public function getMetadata($key = null)
    {
        return $this->stream->getMetadata($key);
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        $this->stream->seek($offset, $whence);
    }

    public function rewind(): void
    {
        $this->stream->rewind();
    }

    public function isReadable(): bool
    {
        return $this->stream->isReadable();
    }

    public function isSeekable(): bool
    {
        return $this->stream->isSeekable();
    }

    public function eof(): bool
    {
        return $this->eof;
    }

    public function write($string): int
    {
        throw new RuntimeException('Stream is not writable');
    }

    public function getContents(): string
    {
        $result = '';
        while (!$this->eof()) {
            $result .= $this->read(1024);
        }
        return $result;
    }

    public function __toString(): string
    {
        return $this->getContents();
    }

    public function detach()
    {
        return $this->stream->detach();
    }

    public function close(): void
    {
        $this->stream->close();
    }
}