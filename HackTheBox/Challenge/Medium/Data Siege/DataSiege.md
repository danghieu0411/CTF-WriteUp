# Data Siege

## Scenario

It was a tranquil night in the Phreaks headquarters, when the entire district erupted in chaos. Unknown assailants, rumored to be a rogue foreign faction, have infiltrated the city's messaging system and critical infrastructure. Garbled transmissions crackle through the airwaves, spewing misinformation and disrupting communication channels. We need to understand which data has been obtained from this attack to reclaim control of the communication backbone. Note: Flag is split into three parts.

## Given artifact

A packet capture file

## Solving process

Skimming through the short PCAP, I immeidately notice suspicious HTTP request, this is a Spring Framework deserialization attack. Looking at the XML in the bottom panel, we can see the smoking gun:

![](1.png)

Grab that file by exporting HTTP object, it turns out to be .NET assembly. So I launch `dnSpy` to analyze it, and it is built from [EZRAT](https://github.com/Exo-poulpe/EZRAT), an open-source platform for red team penetration testing.

After the malware is dropped, weird in-bound and out-bound traffic appear. They are definitely C2 traffic, so firstly I will inspect the encryption schema:

```c#
public static string Encrypt(string clearText)
		{
			string result;
			try
			{
				string encryptKey = Constantes.EncryptKey;
				byte[] bytes = Encoding.Default.GetBytes(clearText);
				using (Aes aes = Aes.Create())
				{
					Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(encryptKey, new byte[]
					{
						86,
						101,
						114,
						121,
						95,
						83,
						51,
						99,
						114,
						51,
						116,
						95,
						83
					});
					aes.Key = rfc2898DeriveBytes.GetBytes(32);
					aes.IV = rfc2898DeriveBytes.GetBytes(16);
					using (MemoryStream memoryStream = new MemoryStream())
					{
						using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
						{
							cryptoStream.Write(bytes, 0, bytes.Length);
							cryptoStream.Close();
						}
						clearText = Convert.ToBase64String(memoryStream.ToArray());
					}
				}
				result = clearText;
			}
			catch (Exception)
			{
				result = clearText;
			}
			return result;
		}
```

The bytes array decodes to:

![](2.png)

And the EncryptKey constant can be found in:

![](3.png)

In short, the encrytion process is:

```text
key, iv = PBKDF2_HMAC_SHA1(password="VYAemVeO3zUDTL6N62kVA",
                           salt=b"Very_S3cr3t_S",
                           iterations=1000,
                           output=48 bytes)
                           # first 32 bytes = key, next 16 = iv

ciphertext = AES_256_CBC_encrypt(plaintext, key, iv) + PKCS7 padding
wire_format = base64(ciphertext)
```

`Rfc2898DeriveBytes` + two `GetBytes` calls is just `PBKDF2` streaming output. `PBKDF2` produces a continuous keystream — calling `GetBytes(32)` then `GetBytes(16)` is identical to asking for 48 bytes once and slicing [0:32] and [32:48]. C# defaults to `HMAC-SHA1` and 1000 iterations on .NET Framework, which is what you want to match.

`Aes.Create()` with no settings uses the .NET defaults: AES-CBC, PKCS7 padding, key size determined by the Key property you assign. Since the code assigns 32 bytes, it's AES-256-CBC. Nothing exotic — same primitive used by basically every legacy crypto-by-tutorial codebase.

So I use a python script to retrieve the Key and IV for AES:

![](21.png)

Now we can start decrypting traffic in the 5-th TCP stream, as there are not so many commands, I copy-paste the traffic to Cyberchef. Were there more commands, copy-pasting would be infeasbile, in that case we would need to use tshark to extract payload and build a script to decode all

Note that for the incoming commands, we need to strip the first number and the dot (in fact it is § character but wireshark cannot display) before decrypting, that number denotes the length of the command that will be sent:

![](4.png)

![](5.png)

![](6.png)

![](7.png)

![](8.png)

![](9.png)

![](10.png)

![](11.png)

![](12.png)

After some initial reconaissance, the attacker puts a new SSH key into the victim's `authorized_keys`, creating a backdoor and maintaining access. We also get the first flag fragment here

![](13.png)

![](14.png)

![](15.png)

![](16.png)

The careless user even store his credentials in a text file, the attacker now even does not have to use the created backdoor, just log in as the legitimate user. We also get the next flag part in this response

![](17.png)

![](18.png)

![](20.png)

The next command is to up a file to the victim machine, the mechanism will be different:

![](22.png)

File is transfer in plaintext, no encoding, no encryption. So we just need to decode the powershell script (it's encoded by the -encode parameter, not the C2 framework):

![](19.png)

This script maintains persistence with scheduled task, whose name is also the final flag fragment!

`Flag: HTB{c0mmun1c4710n5_h45_b33n_r3570r3d_1n_7h3_h34dqu4r73r5}`