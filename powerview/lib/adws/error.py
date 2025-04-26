import xml.etree.ElementTree as ET
from .templates import NAMESPACES
class ADWSError(Exception):
    """Custom exception for ADWS SOAP Faults."""
    def __init__(self, fault_data):
        self.raw_fault = fault_data if isinstance(fault_data, str) else fault_data.get("RawXML", "")
        self.detail_error = "Unknown ADWS Error"
        self.message = None
        self.errorcode = None
        self.fault_data = fault_data

        try:
            if isinstance(fault_data, str):
                # Handle raw XML string
                if fault_data.startswith("Sorting or Selection Property is invalid."):
                    xml_start = fault_data.find("<")
                    if xml_start != -1:
                        fault_data = fault_data[xml_start:]

                for prefix, uri in NAMESPACES.items():
                    ET.register_namespace(prefix, uri)

                root = ET.fromstring(fault_data)

                detail_element = root.find(".//soapenv:Detail", NAMESPACES) or root.find(".//s:Detail", NAMESPACES)
                if detail_element is not None:
                    dir_error = detail_element.find(".//ad:DirectoryError", NAMESPACES)
                    if dir_error is not None:
                        msg_elem = dir_error.find(".//ad:Message", NAMESPACES)
                        code_elem = dir_error.find(".//ad:ErrorCode", NAMESPACES)
                        if msg_elem is not None and msg_elem.text:
                            self.message = msg_elem.text.strip()
                        if code_elem is not None and code_elem.text:
                            try:
                                self.errorcode = int(code_elem.text.strip())
                            except Exception:
                                self.errorcode = code_elem.text.strip()
                        if self.message:
                            self.detail_error = self.message
                            super().__init__(self.detail_error)
                            return
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

            elif isinstance(fault_data, dict):
                # Handle dictionary data
                self.message = fault_data.get("Error")
                self.errorcode = fault_data.get("FaultCode")
                self.detail_error = fault_data.get("Error", "Unknown ADWS Error")

                if "ErrorDetail" in fault_data:
                    error_detail = fault_data["ErrorDetail"]
                    if "FaultDetail" in error_detail:
                        fault_detail = error_detail["FaultDetail"]
                        if "DirectoryError" in fault_detail:
                            dir_error = fault_detail["DirectoryError"]
                            self.message = dir_error.get("Message")
                            self.errorcode = dir_error.get("ErrorCode")
                            extended_error = dir_error.get("ExtendedErrorMessage")
                            if extended_error:
                                self.detail_error = extended_error
                            elif self.message:
                                self.detail_error = self.message
                        elif "ArgumentError" in fault_detail:
                            arg_error = fault_detail["ArgumentError"]
                            self.message = arg_error.get("Message")
                            # ArgumentError might not have a standard ErrorCode,
                            # but we can capture ShortMessage if available
                            self.errorcode = arg_error.get("ShortMessage")
                            if self.message:
                                self.detail_error = self.message
                        elif "ExtendedErrorMessage" in fault_detail:
                            self.detail_error = fault_detail["ExtendedErrorMessage"]
                        elif "ExtendedErrorDescription" in fault_detail:
                            self.detail_error = fault_detail["ExtendedErrorDescription"]
                    elif "Message" in error_detail:
                        self.message = error_detail.get("Message")
                        self.detail_error = self.message
            elif isinstance(fault_data, list):
                # Handle list data
                self.detail_error = "Multiple ADWS Errors"
                self.message = "Multiple ADWS Errors"
                self.errorcode = "Multiple"

        except ET.ParseError:
            self.detail_error = self.raw_fault.split("<")[0].strip() if "<" in self.raw_fault else self.raw_fault
        except Exception:
            pass

        super().__init__(self.detail_error)

    def __str__(self):
        return self.detail_error