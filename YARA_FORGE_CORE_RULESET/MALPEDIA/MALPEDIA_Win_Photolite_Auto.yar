rule MALPEDIA_Win_Photolite_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "91b305a0-4121-51a1-b4d2-2f8343c04744"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.photolite"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.photolite_auto.yar#L1-L166"
		license_url = "N/A"
		logic_hash = "caefd484ddfe657e42e053f8e8452f60715f0696ed8aba66627e49aa5e3366fe"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { c7859802000042cc7257 c7859c02000075cc545d c785a002000040c02638 8b8594020000 8a8590020000 84c0 751e }
		$sequence_1 = { ff15???????? 498bd6 488d4d76 ff15???????? 8a4301 }
		$sequence_2 = { c7859405000037f43a3a c785980500002fef391c c7859c0500000be1241d c785a00500002fe54a79 8b8590050000 8a858c050000 84c0 }
		$sequence_3 = { 8a85e0020000 84c0 751e 488bcb 8b848de4020000 }
		$sequence_4 = { 4803cf 483bce 72e5 885c244c c744245057106c10 c7442454556a4c30 }
		$sequence_5 = { 8bc3 4d03ca 85d2 7474 448bc0 }
		$sequence_6 = { 7421 0f1002 488bc2 482bc6 482bc7 }
		$sequence_7 = { 7307 488b7c2430 eba3 488b5c2448 }
		$sequence_8 = { 48895d38 48895da0 895d30 488b01 ff5070 8bf8 85c0 }
		$sequence_9 = { 488bd8 4885c0 0f8419010000 488b15???????? }
		$sequence_10 = { 488bcb ffd0 ffc6 41b8bb010000 8bd6 }
		$sequence_11 = { 84c0 0f85f5000000 4885db 7451 488b05???????? 4885c0 7426 }
		$sequence_12 = { 72e9 4c8d442444 41b901000000 488d047e 410fb6d1 }
		$sequence_13 = { 3dc8000000 0f849d000000 488b5d28 4885db }
		$sequence_14 = { 75f2 33db 4084f6 0f84e6000000 }
		$sequence_15 = { 488d542474 488d8de0020000 ff15???????? 408874245c }

	condition:
		7 of them and filesize <99328
}