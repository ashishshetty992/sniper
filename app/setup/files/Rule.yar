rule Pafish{

	meta:
		author = "Nada"
		description = "This is an example of a Malicious file."
		sha256 = "2180f4a13add5e346e8cf6994876a9d2f5eac3fcb695db8569537010d24cd6d5"
	strings:
		$hex_string1 = { E8 C9 36 00 00 }
	    	$ = "%WINDOWS_COPYRIGHT%" wide
	    	$ = "Cmd.Exe" wide
	    	$ = "Windows Command Processor" wide
	
	condition:
		any of them
}
