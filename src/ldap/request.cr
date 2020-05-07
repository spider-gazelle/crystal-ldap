require "mutex"
require "../ldap"

class LDAP::Request
  @msg_id = -1
  @id_mutex = Mutex.new

  def next_message_id
    @id_mutex.synchronize {
      begin
        @msg_id = @msg_id + 1
      rescue OverflowError
        @msg_id = 0
      end
    }
  end

  def build(request : BER, controls : BER? = nil, message_id = next_message_id)
    # construct message id
    id_ber = BER.new.set_integer(message_id)
    sequence = controls ? {id_ber, request, controls} : {id_ber, request}
    {message_id, LDAP.sequence(sequence)}
  end

  START_TLS_OID = "1.3.6.1.4.1.1466.20037"

  def start_tls
    build(LDAP.app_sequence({
      BER.new.set_string(START_TLS_OID, 0, TagClass::ContextSpecific),
    }, Tag::ExtendedRequest))
  end

  def authenticate(username : String = "", password : String = "")
    build(LDAP.app_sequence({
      BER.new.set_integer(3),
      BER.new.set_string(username, UniversalTags::OctetString),
      BER.new.set_string(password, 0, TagClass::ContextSpecific),
    }, Tag::BindRequest))
  end
end
