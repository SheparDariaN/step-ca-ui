package casync

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Ключ Badger в smallstep/nosql: [uint16 LE длина бакета][бакет][uint16 LE длина ключа][ключ].
// Маркер таблицы — только первая секция, без ключа.

func encodeSection(val []byte) ([]byte, error) {
	if len(val) == 0 || len(val) > 65535 {
		return nil, fmt.Errorf("badger section length %d", len(val))
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, uint16(len(val))); err != nil {
		return nil, err
	}
	buf.Write(val)
	return buf.Bytes(), nil
}

func toBadgerKey(bucket, key []byte) ([]byte, error) {
	first, err := encodeSection(bucket)
	if err != nil {
		return nil, err
	}
	second, err := encodeSection(key)
	if err != nil {
		return nil, err
	}
	return append(first, second...), nil
}

func parseSection(bk []byte) (value, rest []byte) {
	if len(bk) < 2 {
		return nil, bk
	}
	var n uint16
	if err := binary.Read(bytes.NewReader(bk[:2]), binary.LittleEndian, &n); err != nil {
		return nil, bk
	}
	end := int(2 + n)
	if len(bk) < end {
		return nil, bk
	}
	if len(bk) == end {
		return bk[2:end], nil
	}
	return bk[2:end], bk[end:]
}

func isTableKey(bk []byte) bool {
	val, rest := parseSection(bk)
	return len(val) > 0 && len(rest) == 0
}

func fromBadgerKey(bk []byte) (bucket, key []byte, err error) {
	bucket, rest := parseSection(bk)
	if len(bucket) == 0 || len(rest) == 0 {
		return nil, nil, fmt.Errorf("invalid badger key")
	}
	key, rest = parseSection(rest)
	if len(key) == 0 || len(rest) != 0 {
		return nil, nil, fmt.Errorf("invalid badger key")
	}
	return bucket, key, nil
}
