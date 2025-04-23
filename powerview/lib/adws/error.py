import xml.etree.ElementTree as ET
from .templates import NAMESPACES

class ADWSError(Exception):
    """Custom exception for ADWS SOAP Faults."""
    def __init__(self, fault_string):
        self.raw_fault = fault_string
        self.detail_error = "Unknown ADWS Error"

        try:
            if fault_string.startswith("Sorting or Selection Property is invalid."):
                 xml_start = fault_string.find("<")
                 if xml_start != -1:
                     fault_string = fault_string[xml_start:]

            for prefix, uri in NAMESPACES.items():
                 ET.register_namespace(prefix, uri)

            root = ET.fromstring(fault_string)

            detail_element = root.find(".//soapenv:Detail", NAMESPACES) or root.find(".//s:Detail", NAMESPACES)
            if detail_element is not None:
                enum_fault = detail_element.find(".//ad:EnumerateFault", NAMESPACES)
                if enum_fault is not None:
                    error_element = enum_fault.find(".//ad:Error", NAMESPACES)
                    if error_element is not None and error_element.text:
                        self.detail_error = error_element.text.strip()
                        super().__init__(self.detail_error)
                        return

            reason_element = root.find(".//soapenv:Text", NAMESPACES) or root.find(".//s:Text", NAMESPACES)
            if reason_element is not None and reason_element.text:
                self.detail_error = reason_element.text.strip()

        except ET.ParseError:
            self.detail_error = self.raw_fault.split("<")[0].strip() if "<" in self.raw_fault else self.raw_fault
        except Exception:
            pass

        super().__init__(self.detail_error)

    def __str__(self):
        return self.detail_error 