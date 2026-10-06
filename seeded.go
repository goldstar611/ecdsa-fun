func ECDSA256KeyPairFromSeed(seed []byte) (d *big.Int, x *big.Int, y *big.Int) {
	curve := elliptic.P256()

	// Deterministically derive bytes from the seed.
	secret := seed
	salt := []byte("optional salt")
	info := []byte("my application context")

	// HKDF-Extract + HKDF-Expand
	reader := hkdf.New(sha512.New, secret, salt, info)

	key := make([]byte, 32) // derive 32 bytes
	if _, err := io.ReadFull(reader, key); err != nil {
		panic(err)
	}

	// Convert key to an integer and reduce modulo the curve order.
	d = new(big.Int).SetBytes(key[:])
	d.Mod(d, curve.Params().N)

	// d must be in [1, N-1].
	if d.Sign() != 1 {
		return ECDSA256KeyPairFromSeed(append(seed, 0x00))
	}

	// Public key = d * G
	x, y = curve.ScalarBaseMult(d.Bytes())

	// Verify that X and Y are greater than 0 and less than p
	p := curve.Params().P
	if x.Sign() != 1 || x.Cmp(p) >= 0 ||
		y.Sign() != 1 || y.Cmp(p) >= 0 {
		fmt.Println("non-canonical point coordinates")
	}

	// Verify that X and Y land on the P-256 curve
	if curve.IsOnCurve(x, y) {
		fmt.Println("valid P-256 point")
	} else {
		fmt.Println("NOT a valid P-256 point")
	}

	return d, x, y
}
