Lightshare SQLite App - Enhanced File Sharing Platform

FEATURES IMPLEMENTED:
✅ Workspace creation with database validation (prevents duplicate names)
✅ Workspace joining with existence verification
✅ Creator-only workspace deletion functionality
✅ User dropdown showing all workspace members + "All" option
✅ File-type specific encryption:
   - PDF: CRC32 encryption with integrity verification
   - Image: Hamming code error correction
   - Video: AES-GCM encryption
✅ In-chat file viewing (PDF, images, videos)
✅ Error detection and automatic retransmission after 1 minute
✅ Sender acknowledgment vs receiver view functionality
✅ End workspace button (creator only) - removes all users and returns to get-started page

SETUP:
1. cd backend
2. npm install
3. npm start
4. Open http://localhost:3000/index.html

DATABASE:
- SQLite database: backend/lightshare.db (auto-created)
- Tables: users, workspaces, workspace_members
- Workspace names are unique and case-insensitive

SECURITY:
- User authentication with bcrypt password hashing
- Session-based authentication
- File encryption with multiple algorithms based on file type
- CRC32 integrity verification for PDFs
- Hamming code error correction for images

WORKFLOW:
1. Sign up/Login → get-started.html
2. Create workspace (checks for duplicates) OR Join workspace (checks existence)
3. Select recipient from dropdown (All users + individual members)
4. Choose file type and upload
5. Receiver gets "View" button to see file in chat
6. Sender gets acknowledgment message
7. Creator can "End Workspace" to delete and return all users to get-started page

ERROR HANDLING:
- File corruption detection triggers automatic retransmission after 1 minute
- Maximum 5 retransmission attempts before marking as failed
- Real-time error feedback to users
- Comprehensive logging for debugging
