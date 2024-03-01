rule MALPEDIA_Win_Gacrux_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0c66c13b-77d9-5c78-ab68-75b7e55560db"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gacrux"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.gacrux_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "bb1a910d98caf8e19645b8aead4c6d896507b388f794dfe868a61d77f59f135d"
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
		$sequence_0 = { 0f848e000000 41 83482120 49 8b01 49 83c108 }
		$sequence_1 = { 894808 48 8b4c2430 48 894810 8b4c2444 }
		$sequence_2 = { 48 03ca 849c013c010000 740b 41 81cb00300000 45 }
		$sequence_3 = { 6bc838 48 8b05???????? 8b540120 c1ea02 1bd2 3bd6 }
		$sequence_4 = { 7543 48 85db 7409 }
		$sequence_5 = { 8b3a 48 8bcd 48 c1e91d 48 8bc5 }
		$sequence_6 = { 41 ffc1 49 83c204 41 81f900010000 }
		$sequence_7 = { 0fb7ee 66c1ed08 45 8a780c 45 8bda 45 }
		$sequence_8 = { 56 41 57 48 83ec50 49 63e8 }
		$sequence_9 = { 4d 033e 45 0fb6ed 49 8bcf }

	condition:
		7 of them and filesize <122880
}
