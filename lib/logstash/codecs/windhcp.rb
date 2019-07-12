# encoding: utf-8
require "logstash/util/charset"
require "logstash/codecs/base"

class LogStash::Codecs::Windhcp < LogStash::Codecs::Base
  config_name "windhcp"
  # Array contenente i nomi dei campi che compongono il log DHCP
  LOG_FIELDS = ["ID","Date","Time","Description","IP Address","HostName","MAC Address","UserName",
	"TransactionID","QResult","ProbationTime","CorrelationID","Dhcid","VendorClass(Hex)",
	"VendorClass(ASCII)","UserClass(HEX)","UserClass(ASCII)","RelayAgentInformation",
	"DnsRegError"]    

  # Regexp per individuare i diversi campi del log indicando il separatore: ',' 
  LOG_PATTERN = /(?:\\\||\\\\|[^|])*?/
  LOG_SCANNER = /(#{LOG_PATTERN})#{Regexp.quote(',')}/
  
  # Regexp per trovare escape character (backslash e pipe)
  ESCAPE_CAPTURE = /\\([\\|])/

  public
  def initialize(params={})
    super(params)
    # Input deve essere codificato in UTF-8
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger
  end
   
  # Definiamo il parser
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
	 
    # Con il seguente ciclo ricaviamo le diverse parti del log
    LOG_FIELDS.each do |field_name|
      # Scansioniamo il log fino al prossimo elemento di separazione (',')
      match_data = LOG_SCANNER.match(unprocessed_data)
      # Se il match non da risultato allora andiamo avanti
      break if match_data.nil?
      # Il valore trovatoo va nella seguente variabile
      escaped_field_value = match_data[1]

      # La prossima parte di codice viene saltata se la condizione è verificata
      next if escaped_field_value.nil?
      # Controlliamo la presenza di escape sequence e rimuoviamo per evitare ambiguità
      unescaped_field_value = escaped_field_value.gsub(ESCAPE_CAPTURE, '\1')
      # Nell'evento settiamo la coppia campo-valore trovata
      event.set(field_name, unescaped_field_value)
      # Conserviamo in unprocessed data tutto quello che c'è dopo il match
      unprocessed_data = match_data.post_match
    end
    
    # Aggiungiamo il log non parsato
    event.set("RAW_MESSAGE", data)

    # Portiamo in uscita l'evento
    yield event

    # In caso di errore viene mostrato il seguente messaggio
    rescue => e
      @logger.error("Failed to decode Windows DHCP payload. Generating failure event with payload in message field.", :error => e.message, :backtrace => e.backtrace, :data => data)
      yield LogStash::Event.new("message" => data, "tags" => ["_WinDHCPparsefailure"])
    end
end
