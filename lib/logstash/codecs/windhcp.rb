# encoding: utf-8
require "logstash/util/charset"
require "logstash/codecs/base"

class LogStash::Codecs::Windhcp < LogStash::Codecs::Base
  config_name "windhcp"
 
  HEADER_FIELDS = ["ID","Date","Time","Description","IP Address","HostName","MAC Address","UserName",
	"TransactionID","QResult","ProbationTime","CorrelationID","Dhcid","VendorClass(Hex)",
	"VendorClass(ASCII)","UserClass(HEX)","UserClass(ASCII)","RelayAgentInformation",
	"DnsRegError"]    

  # Queste espressioni servono per individuare l'header. 
  HEADER_PATTERN = /(?:\\\||\\\\|[^|])*?/
  
  # Per trovare i campi dell'header indico il separatore: '|'
  HEADER_SCANNER = /(#{HEADER_PATTERN})#{Regexp.quote(',')}/
  
  # Cache of a gsub pattern that matches a backslash-escaped backslash or backslash-escaped pipe, _capturing_ the escaped character
  HEADER_ESCAPE_CAPTURE = /\\([\\|])/

  public
  def initialize(params={})
    super(params)
    # Input deve essere codificato in UTF-8
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger
  end
   
  # Definiamo il parser vero e proprio
  def decode(data, &block)
    # Creiamo l'evento
    event = LogStash::Event.new

    # Usiamo per il log la codifica UTF-8
    @utf8_charset.convert(data)
    # Se l'encoding non ha avuto successo non andiamo avanti nel parsing, perchè nascerebbero errori
    fail('invalid byte sequence in UTF-8') unless data.valid_encoding?

    # Nel caso ci siano caratteri a delimitare l'inizio e alla fine del log, vengono rimossi
    if data[0] == "\""
      data = data[1..-2]
    end
    
    # Il log da parsare viene inserito in una variabile dal nome unprocessed_data
    unprocessed_data = data
	 
    # Scopo di questo ciclo è ricavare le diverse parti dell'header
    HEADER_FIELDS.each do |field_name|
      # Scansioniamo l'header fino al prossimo elemento di separazione (',')
      match_data = HEADER_SCANNER.match(unprocessed_data)
      # Se non c'è match allora il campo manca e andiamo avanti
      break if match_data.nil?
      # Il valore matchato va nella seguente variabile
      escaped_field_value = match_data[1]

      # La prossima parte di codice viene saltata se la condizione è verificata
      next if escaped_field_value.nil?
      # Controlliamo la presenze di sequenze di escape e rimuoviamo per evitare ambiguità
      unescaped_field_value = escaped_field_value.gsub(HEADER_ESCAPE_CAPTURE, '\1')
      # A questo punto nell'evento settiamo la coppia header-valore trovata
      event.set(field_name, unescaped_field_value)
      # Conserviamo in unprocessed data tutto quello che c'è dopo il match
      unprocessed_data = match_data.post_match
    end

    # Portiamo in uscita l'evento
    yield event

    # In caso di errore viene mostrato il seguente messaggio
    rescue => e
      @logger.error("Failed to decode Windows DHCP payload. Generating failure event with payload in message field.", :error => e.message, :backtrace => e.backtrace, :data => data)
      yield LogStash::Event.new("message" => data, "tags" => ["_WinDHCPparsefailure"])
    end
end
