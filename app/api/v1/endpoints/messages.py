from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from datetime import datetime
from typing import List
import uuid
import base64

from app.core.database import get_db
from app.core.security import KyberKEM, AESCipher, decapsulate_key
from app.models.models import Message, User
from app.schemas.schemas import MessageCreate, MessageResponse, MessageList, ConversationResponse
from app.api.v1.endpoints.auth import get_current_user
from Crypto.Random import get_random_bytes

router = APIRouter()

class MessageDecryptionService:
    """
    Service to decrypt messages on the backend before sending to frontend
    """
    
    @staticmethod
    def decrypt_aes_gcm(encrypted_data: bytes, shared_secret: bytes) -> bytes:
        """
        Decrypt data using AES-GCM with the shared secret
        """
        try:
            print(f"  AES Decryption - Encrypted data length: {len(encrypted_data)}")
            print(f"  AES Decryption - Shared secret length: {len(shared_secret)}")
            
            # Extract IV (first 16 bytes) and tag (next 16 bytes) and ciphertext
            if len(encrypted_data) < 32:
                raise Exception(f"Encrypted data too short: {len(encrypted_data)} bytes (need at least 32)")
                
            iv = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            print(f"  AES Decryption - IV length: {len(iv)}")
            print(f"  AES Decryption - Tag length: {len(tag)}")
            print(f"  AES Decryption - Ciphertext length: {len(ciphertext)}")
            
            # Create cipher using first 32 bytes of shared secret for AES-256
            if len(shared_secret) < 32:
                raise Exception(f"Shared secret too short: {len(shared_secret)} bytes (need at least 32)")
                
            cipher = AESCipher(shared_secret[:32])
            
            # For GCM mode, we need to reconstruct the encrypted data format
            # that AESCipher.decrypt expects (iv + tag + ciphertext)
            reconstructed_data = iv + tag + ciphertext
            
            print(f"  AES Decryption - Reconstructed data length: {len(reconstructed_data)}")
            
            decrypted_data = cipher.decrypt(reconstructed_data)
            
            print(f"  AES Decryption - Success! Decrypted length: {len(decrypted_data)}")
            
            return decrypted_data
            
        except Exception as e:
            print(f"  AES Decryption - Error: {str(e)}")
            raise Exception(f"AES decryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_message_content(encrypted_content: bytes, encrypted_key: bytes, recipient_private_key: bytes) -> str:
        """
        Decrypt a message using Kyber KEM + AES-GCM
        
        Args:
            encrypted_content: Encrypted message content (bytes)
            encrypted_key: Encapsulated symmetric key (bytes)
            recipient_private_key: Recipient's Kyber private key (bytes)
            
        Returns:
            Decrypted message content as string
        """
        try:
            print(f"  Starting message decryption...")
            print(f"  Encrypted content type: {type(encrypted_content)}")
            print(f"  Encrypted key type: {type(encrypted_key)}")
            print(f"  Private key type: {type(recipient_private_key)}")
            
            # Ensure all inputs are bytes
            if not isinstance(encrypted_content, bytes):
                print(f"  Converting encrypted_content from {type(encrypted_content)} to bytes")
                if isinstance(encrypted_content, str):
                    encrypted_content = base64.b64decode(encrypted_content)
                else:
                    encrypted_content = bytes(encrypted_content)
                    
            if not isinstance(encrypted_key, bytes):
                print(f"  Converting encrypted_key from {type(encrypted_key)} to bytes")
                if isinstance(encrypted_key, str):
                    encrypted_key = base64.b64decode(encrypted_key)
                else:
                    encrypted_key = bytes(encrypted_key)
                    
            if not isinstance(recipient_private_key, bytes):
                print(f"  Converting private_key from {type(recipient_private_key)} to bytes")
                if isinstance(recipient_private_key, str):
                    recipient_private_key = base64.b64decode(recipient_private_key)
                else:
                    recipient_private_key = bytes(recipient_private_key)
            
            print(f"  Final lengths - Content: {len(encrypted_content)}, Key: {len(encrypted_key)}, PrivKey: {len(recipient_private_key)}")
            
            # Step 1: Decapsulate the symmetric key using Kyber
            print(f"  Step 1: Decapsulating symmetric key with Kyber...")
            shared_secret = decapsulate_key(encrypted_key, recipient_private_key)
            print(f"  Kyber decapsulation successful, shared secret length: {len(shared_secret)}")
            
            # Step 2: Decrypt the message content using AES-GCM
            print(f"  Step 2: Decrypting content with AES-GCM...")
            decrypted_bytes = MessageDecryptionService.decrypt_aes_gcm(encrypted_content, shared_secret)
            
            # Step 3: Convert to string
            print(f"  Step 3: Converting to UTF-8 string...")
            decrypted_text = decrypted_bytes.decode('utf-8')
            
            print(f"  ✅ Message decryption successful!")
            return decrypted_text
            
        except Exception as e:
            print(f"  ❌ Message decryption failed: {str(e)}")
            import traceback
            traceback.print_exc()
            raise Exception(f"Failed to decrypt message: {str(e)}")
        
@router.get("/debug/message/{message_id}")
async def debug_message(
    message_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Debug endpoint to inspect message data
    """
    try:
        # Get the message
        query = select(Message).where(Message.id == message_id)
        result = await db.execute(query)
        message = result.scalar_one_or_none()
        
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")
        
        # Get sender and recipient info
        sender_query = select(User).where(User.id == message.sender_id)
        sender_result = await db.execute(sender_query)
        sender = sender_result.scalar_one_or_none()
        
        recipient_query = select(User).where(User.id == message.recipient_id)
        recipient_result = await db.execute(recipient_query)
        recipient = recipient_result.scalar_one_or_none()
        
        debug_info = {
            "message_id": str(message.id),
            "sender": {
                "id": str(message.sender_id),
                "username": sender.username if sender else "Unknown",
                "has_private_key": bool(sender.kyber_private_key) if sender else False,
                "private_key_length": len(sender.kyber_private_key) if sender and sender.kyber_private_key else 0
            },
            "recipient": {
                "id": str(message.recipient_id),
                "username": recipient.username if recipient else "Unknown", 
                "has_private_key": bool(recipient.kyber_private_key) if recipient else False,
                "private_key_length": len(recipient.kyber_private_key) if recipient and recipient.kyber_private_key else 0
            },
            "message_data": {
                "subject": message.subject,
                "created_at": message.created_at.isoformat(),
                "encrypted_content_type": str(type(message.encrypted_content)),
                "encrypted_content_length": len(message.encrypted_content) if message.encrypted_content else 0,
                "encrypted_key_type": str(type(message.encrypted_symmetric_key)),
                "encrypted_key_length": len(message.encrypted_symmetric_key) if message.encrypted_symmetric_key else 0,
                "is_deleted": message.is_deleted
            }
        }
        
        return {
            "success": True,
            "debug_info": debug_info
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@router.post("/send", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def send_message(
    message_data: MessageCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get recipient's public key
    query = select(User).where(User.id == message_data.recipient_id)
    result = await db.execute(query)
    recipient = result.scalar_one_or_none()
    
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found"
        )
    
    # Generate AES key for message encryption
    aes_key = get_random_bytes(32)
    cipher = AESCipher(aes_key)
    
    # Encrypt message content
    encrypted_content = cipher.encrypt(message_data.content.encode())
    
    # Encrypt AES key with recipient's Kyber public key
    encrypted_key, _ = KyberKEM.encapsulate(recipient.kyber_public_key)
    
    # Create message
    db_message = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        subject=message_data.subject,
        encrypted_content=encrypted_content,
        encrypted_symmetric_key=encrypted_key
    )
    
    db.add(db_message)
    await db.commit()
    await db.refresh(db_message)
    
    return db_message

@router.get("/conversation/{recipient_id}")
async def get_conversation(
    recipient_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get conversation messages between current user and recipient
    Returns messages with decrypted content
    """
    try:
        print(f"=== Getting conversation between user {current_user.id} and {recipient_id} ===")
        
        # Validate recipient exists
        recipient_query = select(User).where(User.id == recipient_id)
        recipient_result = await db.execute(recipient_query)
        recipient = recipient_result.scalar_one_or_none()
        
        if not recipient:
            print(f"ERROR: Recipient {recipient_id} not found")
            return {
                'success': False,
                'error': 'Recipient not found', 
                'messages': []
            }
        
        print(f"Current user: {current_user.username} (ID: {current_user.id})")
        print(f"Recipient: {recipient.username} (ID: {recipient.id})")
        
        # Check if both users have encryption keys
        if not current_user.kyber_private_key:
            print(f"ERROR: Current user {current_user.username} has no private key")
        if not recipient.kyber_private_key:
            print(f"ERROR: Recipient {recipient.username} has no private key")
            
        # Get messages from database
        query = select(Message).where(
            or_(
                and_(Message.sender_id == current_user.id, Message.recipient_id == recipient_id),
                and_(Message.sender_id == recipient_id, Message.recipient_id == current_user.id)
            )
        ).order_by(Message.created_at.asc())
        
        result = await db.execute(query)
        messages = result.scalars().all()
        
        print(f"Found {len(messages)} messages in database")
        
        decrypted_messages = []
        
        for i, message in enumerate(messages):
            print(f"\n--- Processing message {i+1}/{len(messages)} (ID: {message.id}) ---")
            print(f"Sender ID: {message.sender_id}")
            print(f"Recipient ID: {message.recipient_id}")
            print(f"Subject: {message.subject}")
            print(f"Created: {message.created_at}")
            
            try:
                # Determine who should decrypt this message
                if message.recipient_id == current_user.id:
                    print(f"Current user is recipient - using current user's private key")
                    private_key = current_user.kyber_private_key
                    key_owner = "current_user"
                else:
                    print(f"Current user is sender - using recipient's private key")  
                    private_key = recipient.kyber_private_key
                    key_owner = "recipient"
                
                if not private_key:
                    raise Exception(f"No private key available for {key_owner}")
                
                print(f"Private key length: {len(private_key)} bytes")
                print(f"Encrypted content length: {len(message.encrypted_content)} bytes")
                print(f"Encrypted key length: {len(message.encrypted_symmetric_key)} bytes")
                
                # Try to decrypt
                decrypted_content = MessageDecryptionService.decrypt_message_content(
                    message.encrypted_content,
                    message.encrypted_symmetric_key,
                    private_key
                )
                
                print(f"✅ Successfully decrypted message: {decrypted_content[:50]}...")
                
                # Get sender info
                sender_query = select(User).where(User.id == message.sender_id)
                sender_result = await db.execute(sender_query)
                sender = sender_result.scalar_one_or_none()
                
                decrypted_messages.append({
                    'id': str(message.id),
                    'sender_id': str(message.sender_id),
                    'recipient_id': str(message.recipient_id),
                    'subject': message.subject or '',
                    'decrypted_content': decrypted_content,
                    'created_at': message.created_at.isoformat(),
                    'read_at': message.read_at.isoformat() if message.read_at else None,
                    'is_deleted': message.is_deleted,
                    'sender_username': sender.username if sender else 'Unknown',
                    'decryption_failed': False
                })
                
            except Exception as decrypt_error:
                print(f"❌ Failed to decrypt message {message.id}: {str(decrypt_error)}")
                print(f"Error type: {type(decrypt_error).__name__}")
                
                # Get sender info even for failed decryption
                sender_query = select(User).where(User.id == message.sender_id)
                sender_result = await db.execute(sender_query)
                sender = sender_result.scalar_one_or_none()
                
                decrypted_messages.append({
                    'id': str(message.id),
                    'sender_id': str(message.sender_id),
                    'recipient_id': str(message.recipient_id),
                    'subject': message.subject or '',
                    'decrypted_content': f'[Message could not be decrypted: {str(decrypt_error)[:100]}]',
                    'created_at': message.created_at.isoformat(),
                    'read_at': message.read_at.isoformat() if message.read_at else None,
                    'is_deleted': message.is_deleted,
                    'sender_username': sender.username if sender else 'Unknown',
                    'decryption_failed': True
                })
        
        print(f"\n=== Summary ===")
        print(f"Total messages processed: {len(messages)}")
        print(f"Successfully decrypted: {len([m for m in decrypted_messages if not m.get('decryption_failed', False)])}")
        print(f"Failed decryptions: {len([m for m in decrypted_messages if m.get('decryption_failed', False)])}")
        
        return {
            'success': True,
            'messages': decrypted_messages
        }
        
    except Exception as e:
        print(f"CRITICAL ERROR in get_conversation: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'error': f"Failed to load conversation: {str(e)}",
            'messages': []
        }

@router.get("/inbox", response_model=MessageList)
async def get_inbox(
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get total count
    count_query = select(Message).where(
        and_(
            Message.recipient_id == current_user.id,
            Message.is_deleted == False
        )
    )
    result = await db.execute(count_query)
    total = len(result.scalars().all())
    
    # Get messages with pagination
    query = select(Message).where(
        and_(
            Message.recipient_id == current_user.id,
            Message.is_deleted == False
        )
    ).order_by(Message.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    messages = result.scalars().all()
    
    return MessageList(messages=messages, total=total)

@router.get("/sent", response_model=MessageList)
async def get_sent_messages(
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get total count
    count_query = select(Message).where(
        and_(
            Message.sender_id == current_user.id,
            Message.is_deleted == False
        )
    )
    result = await db.execute(count_query)
    total = len(result.scalars().all())
    
    # Get messages with pagination
    query = select(Message).where(
        and_(
            Message.sender_id == current_user.id,
            Message.is_deleted == False
        )
    ).order_by(Message.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    messages = result.scalars().all()
    
    return MessageList(messages=messages, total=total)

@router.get("/{message_id}", response_model=MessageResponse)
async def get_message(
    message_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Message).where(
        and_(
            Message.id == message_id,
            or_(
                Message.sender_id == current_user.id,
                Message.recipient_id == current_user.id
            ),
            Message.is_deleted == False
        )
    )
    result = await db.execute(query)
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Mark as read if recipient is accessing
    if message.recipient_id == current_user.id and not message.read_at:
        message.read_at = datetime.utcnow()
        await db.commit()
    
    return message

@router.delete("/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_message(
    message_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Message).where(
        and_(
            Message.id == message_id,
            or_(
                Message.sender_id == current_user.id,
                Message.recipient_id == current_user.id
            ),
            Message.is_deleted == False
        )
    )
    result = await db.execute(query)
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    message.is_deleted = True
    await db.commit()
    return None