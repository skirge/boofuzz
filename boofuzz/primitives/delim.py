from .base_primitive import BasePrimitive


class Delim(BasePrimitive):
    def __init__(self, value=None, fuzzable=True, name=None):
        """
        Represent a delimiter such as :,\r,\n, ,=,>,< etc... Mutations include repetition, substitution and exclusion.

        @type  value:    chr
        @param value:    Original value
        @type  fuzzable: bool
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:     str
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(Delim, self).__init__()

        self._fuzzable = fuzzable
        self._name = name
        self._value = self._original_value = value

        if self._value:
            self._fuzz_library.append(self._value * 2)
            self._fuzz_library.append(self._value * 5)
            self._fuzz_library.append(self._value * 10)
            self._fuzz_library.append(self._value * 25)
            self._fuzz_library.append(self._value * 100)
            self._fuzz_library.append(self._value * 500)
            self._fuzz_library.append(self._value * 1000)

        self._fuzz_library.append("")
        if self._value == " ":
            self._fuzz_library.append("\t")
            self._fuzz_library.append("\t" * 2)
            self._fuzz_library.append("\t" * 100)

        self._fuzz_library.append(" ")
        self._fuzz_library.append("\t")
        self._fuzz_library.append("\t " * 100)
        self._fuzz_library.append("\t\r\n" * 100)
        self._fuzz_library.append("!")
        self._fuzz_library.append("@")
        self._fuzz_library.append("#")
        self._fuzz_library.append("$")
        self._fuzz_library.append("%")
        self._fuzz_library.append("^")
        self._fuzz_library.append("&")
        self._fuzz_library.append("*")
        self._fuzz_library.append("(")
        self._fuzz_library.append(")")
        self._fuzz_library.append("-")
        self._fuzz_library.append("_")
        self._fuzz_library.append("+")
        self._fuzz_library.append("=")
        self._fuzz_library.append(":")
        self._fuzz_library.append(": " * 100)
        self._fuzz_library.append(":7" * 100)
        self._fuzz_library.append(";")
        self._fuzz_library.append("'")
        self._fuzz_library.append('"')
        self._fuzz_library.append("/")
        self._fuzz_library.append("\\")
        self._fuzz_library.append("?")
        self._fuzz_library.append("<")
        self._fuzz_library.append(">")
        self._fuzz_library.append(".")
        self._fuzz_library.append(",")
        self._fuzz_library.append("\r")
        self._fuzz_library.append("\n")
        self._fuzz_library.append("\r\n" * 64)
        self._fuzz_library.append("\r\n" * 128)
        self._fuzz_library.append("\r\n" * 512)

        self._fuzz_library.append("\x08" * 64)
        self._fuzz_library.append("\x08" * 128)
        self._fuzz_library.append("\x08" * 512)

        self._fuzz_library.append("\x0B" * 64)
        self._fuzz_library.append("\x0B" * 128)
        self._fuzz_library.append("\x0B" * 512)

        self._fuzz_library.append("\x1A")

        # unicode white space characters
        self._fuzz_library.append("\xA0")
        self._fuzz_library.append("\xC2\xA0")
        #self._fuzz_library.append("\u00A0")

        self._fuzz_library.append("\xE3\x80\x80")
        #self._fuzz_library.append("\u3000")

        #self._fuzz_library.append("\u1680")
        self._fuzz_library.append("\xE1\x9A\x80")

        #self._fuzz_library.append("\u2000")
        self._fuzz_library.append("\xE2\x80\x80")

        #self._fuzz_library.append("\u2001")
        self._fuzz_library.append("\xE2\x80\x81")

        #self._fuzz_library.append("\u2003")
        self._fuzz_library.append("\xE2\x80\x83")

        #self._fuzz_library.append("\u2004")
        self._fuzz_library.append("\xE2\x80\x84")

        #self._fuzz_library.append("\u2005")
        self._fuzz_library.append("\xE2\x80\x85")

        #self._fuzz_library.append("\u2006")
        self._fuzz_library.append("\xE2\x80\x86")

        #self._fuzz_library.append("\u2007")
        self._fuzz_library.append("\xE2\x80\x87")

        #self._fuzz_library.append("\u2008")
        self._fuzz_library.append("\xE2\x80\x88")

        #self._fuzz_library.append("\u2009")
        self._fuzz_library.append("\xE2\x80\x89")

        #self._fuzz_library.append("\u200A")
        self._fuzz_library.append("\xE2\x80\x8A")

        #self._fuzz_library.append("\u200B")
        self._fuzz_library.append("\xE2\x80\x8B")

        #self._fuzz_library.append("\u200C")
        self._fuzz_library.append("\xE2\x80\x8C")

        #self._fuzz_library.append("\u200D")
        self._fuzz_library.append("\xE2\x80\x8D")

        #self._fuzz_library.append("\u200E")
        self._fuzz_library.append("\xE2\x80\x8E")

        #self._fuzz_library.append("\u200F")
        self._fuzz_library.append("\xE2\x80\x8F")

        #self._fuzz_library.append("\u202F")
        self._fuzz_library.append("\xE2\x80\xAF")

        #self._fuzz_library.append("\u205F")
        self._fuzz_library.append("\xE2\x81\x9F")

        self._fuzz_library.append("\xE2\x81\xA0")
        #self._fuzz_library.append("\u2060")

        #self._fuzz_library.append("\uFEFF")
        self._fuzz_library.append("\xEF\xBB\xBF")

        self._fuzz_library.append("\xE2\x90\x89")
        #self._fuzz_library.append("\u2409")

        self._fuzz_library.append("\xE2\x90\x8B")
        #self._fuzz_library.append("\u240B")

        self._fuzz_library.append("\xE2\x86\xB9")
        #self._fuzz_library.append("\u21B9")

        self._fuzz_library.append("\xE2\x87\x86")
        #self._fuzz_library.append("\u21C6")

        self._fuzz_library.append("\xE2\x87\xA4")
        #self._fuzz_library.append("\u21E4")

        self._fuzz_library.append("\xE2\x87\xA5")
        #self._fuzz_library.append("\u21E5")

        self._fuzz_library.append("\xEF\xBF\xBD")
        #self._fuzz_library.append("\uFFFD")

        self._fuzz_library.append("\xEF\xBF\xBC")
        #self._fuzz_library.append("\uFFFC")

    @property
    def name(self):
        return self._name
