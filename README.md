# EasyPdb

A very simple C++ library for download pdb, get rva of function, global variable and offset from struct.

---

# usage

```cpp
std::string ntos_path = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
ez::pdb ntos_pdb = ez::pdb(ntos_path);
if (ntos_pdb.init())
{
	int rva_ntclose = ntos_pdb.get_rva("NtClose");
	printf("nt!NtClose = %x\n", rva_ntclose);
}
```

---

# Thanks

https://github.com/Broihon/Symbol-Parser

https://github.com/pod32g/MD5

https://stackoverflow.com/questions/3092609/how-to-get-field-names-and-offsets-of-a-struct-using-dbghlp-and-pdb
